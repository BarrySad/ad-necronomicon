import logging
import json
import codecs

from necronomicon.connection import LDAPSession, LDAP_SERVER_SHOW_DELETED_OID
from necronomicon.utils import format_sid, parse_guid

DELETED_OBJECT_ATTRIBUTES = [
    'name', 'sAMAccountName', 'objectSid', 'objectGUID', 'objectClass',
    'lastKnownParent', 'msDS-LastKnownRDN', 'isDeleted', 'isRecycled',
    'whenCreated', 'whenChanged', 'description', 'info',
    'userAccountControl', 'nTSecurityDescriptor',
]

DEL_MARKER = '\\0ADEL:'


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _is_deleted_dn(dn):
    return dn is not None and (DEL_MARKER in dn or ',cn=deleted objects,' in dn.lower())


def _last_known_rdn(entry):
    attrs = entry['attributes']
    rdn = _first(attrs.get('msDS-LastKnownRDN'))
    if rdn:
        return rdn
    first_component = entry['dn'].split(',', 1)[0].split('=', 1)[1]
    return first_component.split(DEL_MARKER, 1)[0]


def format_deleted_entry(entry, recycle_bin_enabled):
    attrs = entry['attributes']
    parent = _first(attrs.get('lastKnownParent'))
    recycled = bool(_first(attrs.get('isRecycled')))
    objectclass = attrs.get('objectClass') or []
    sid = _first(attrs.get('objectSid'))
    if isinstance(sid, bytes):
        sid = format_sid(sid)
    guid = attrs.get('objectGUID')
    if guid:
        guid = parse_guid(guid)

    return {
        'name': _last_known_rdn(entry),
        'samaccountname': _first(attrs.get('sAMAccountName')),
        'objectclass': objectclass[-1] if objectclass else None,
        'objectsid': sid,
        'objectguid': guid,
        'distinguishedname': entry['dn'],
        'lastknownparent': parent,
        'lastknownparent_deleted': _is_deleted_dn(parent),
        'description': _first(attrs.get('description')),
        'info': _first(attrs.get('info')),
        'useraccountcontrol': _first(attrs.get('userAccountControl')),
        'whencreated': _first(attrs.get('whenCreated')),
        'whendeleted': _first(attrs.get('whenChanged')),
        'isrecycled': recycled,
        'attributes_retained': recycle_bin_enabled and not recycled,
        'restorable': not recycled,
    }


class BinEnumerator:
    def __init__(self, session):
        self.session = session

    def enumerate(self):
        rb_info = self.session.get_recycle_bin_info()
        logging.info('AD Recycle Bin: %s',
                     'ENABLED' if rb_info['enabled'] else 'NOT enabled (tombstones only)')

        controls = self.session.get_deleted_object_controls()
        objects = []
        for entry in self.session.search(
                '(isDeleted=TRUE)',
                DELETED_OBJECT_ATTRIBUTES,
                controls=controls):
            if entry['dn'].lower().startswith('cn=deleted objects'):
                continue
            objects.append(format_deleted_entry(entry, rb_info['enabled']))

        if not objects:
            logging.warning('No deleted objects found. Listing Deleted Objects '
                            'requires List Contents right (Domain Admins by default).')
        else:
            restorable = sum(1 for o in objects if o['restorable'])
            logging.info('Found %d deleted objects (%d restorable)', len(objects), restorable)

        return _structure_output(objects, rb_info)


TYPE_BUCKETS = ['user', 'computer', 'group', 'organizationalUnit']


def _bucket_key(objectclass):
    if not objectclass:
        return 'other'
    low = objectclass.lower()
    for t in TYPE_BUCKETS:
        if low == t.lower():
            return t
    return 'other'


PRIVILEGED_GROUP_KEYWORDS = [
    'domain admins', 'enterprise admins', 'administrators', 'schema admins',
    'account operators', 'server operators', 'backup operators',
    'dnsadmins', 'group policy creator', 'protected users',
    'cert publishers', 'ras and ias', 'exchange',
]

PRIVILEGED_CONTAINERS = [
    'cn=adminsdholder,', 'ou=domain controllers,', 'cn=builtin,',
]


def _assess_value(obj):
    tags = []
    name_lower = (obj.get('name') or '').lower()
    sam_lower = (obj.get('samaccountname') or '').lower()
    parent_lower = (obj.get('lastknownparent') or '').lower()
    obj_type = (obj.get('objectclass') or '').lower()

    if obj_type == 'group':
        for kw in PRIVILEGED_GROUP_KEYWORDS:
            if kw in name_lower or kw in sam_lower:
                tags.append('privileged_group')
                break

    if obj_type == 'computer':
        uac = obj.get('useraccountcontrol')
        if uac and (int(uac) & 0x2000):
            tags.append('domain_controller')

    for container in PRIVILEGED_CONTAINERS:
        if container in parent_lower:
            tags.append('privileged_container')
            break

    if obj.get('description') or obj.get('info'):
        tags.append('has_notes')

    if obj.get('lastknownparent_deleted'):
        tags.append('parent_deleted')

    return tags


def _structure_output(objects, rb_info):
    restorable = [o for o in objects if o['restorable']]
    recycled = [o for o in objects if o['isrecycled']]

    def _group_by_type(subset):
        groups = {}
        for obj in subset:
            key = _bucket_key(obj.get('objectclass'))
            groups.setdefault(key, []).append(obj)
        return groups

    for obj in restorable:
        obj['value_tags'] = _assess_value(obj)

    notable = [o for o in objects
               if o.get('description') or o.get('info')]

    high_value = [o for o in restorable if o.get('value_tags')]

    return {
        'meta': {
            'type': 'deletedobjects',
            'total': len(objects),
            'restorable': len(restorable),
            'recycled': len(recycled),
            'notable': len(notable),
            'high_value': len(high_value),
            'recyclebin': rb_info,
        },
        'restorable': _group_by_type(restorable),
        'recycled': _group_by_type(recycled),
        'high_value': high_value,
        'notable': notable,
    }


def write_output(output, filename):
    with codecs.open(filename, 'w', 'utf-8') as fh:
        json.dump(output, fh, indent=2, default=str)
    logging.info('Output written to %s', filename)
