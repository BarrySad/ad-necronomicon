import logging
import struct
from uuid import UUID

from ldap3 import BASE
from ldap3.protocol.microsoft import security_descriptor_control

from necronomicon.connection import LDAPSession, LDAP_SERVER_SHOW_DELETED_OID
from necronomicon.utils import format_sid, WELL_KNOWN_SIDS, DOMAIN_RELATIVE_SIDS

REANIMATE_TOMBSTONES = '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACCESS_DENIED_ACE_TYPE = 0x01
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06

ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_LIST_CONTENTS = 0x00000004
ADS_RIGHT_DS_LIST_OBJECT = 0x00000080
GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_ALL = 0x000F01FF

ACE_OBJECT_TYPE_PRESENT = 0x01

SD_DACL_OFFSET = 16


def _parse_sd_dacl(sd_bytes):
    if not sd_bytes or len(sd_bytes) < 20:
        return None, []
    dacl_offset = struct.unpack_from('<I', sd_bytes, SD_DACL_OFFSET)[0]
    if dacl_offset == 0 or dacl_offset >= len(sd_bytes):
        return None, []
    owner_offset = struct.unpack_from('<I', sd_bytes, 4)[0]
    owner_sid = None
    if owner_offset and owner_offset + 8 <= len(sd_bytes):
        sub_count = sd_bytes[owner_offset + 1]
        sid_len = 8 + 4 * sub_count
        if owner_offset + sid_len <= len(sd_bytes):
            owner_sid = format_sid(sd_bytes[owner_offset:owner_offset + sid_len])

    pos = dacl_offset
    if pos + 8 > len(sd_bytes):
        return owner_sid, []
    _acl_rev = sd_bytes[pos]
    acl_size = struct.unpack_from('<H', sd_bytes, pos + 2)[0]
    ace_count = struct.unpack_from('<H', sd_bytes, pos + 4)[0]
    pos += 8

    aces = []
    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            break
        ace_type = sd_bytes[pos]
        ace_flags = sd_bytes[pos + 1]
        ace_size = struct.unpack_from('<H', sd_bytes, pos + 2)[0]
        if ace_size < 4 or pos + ace_size > len(sd_bytes):
            break

        ace_data = sd_bytes[pos:pos + ace_size]
        parsed = _parse_ace(ace_type, ace_data)
        if parsed:
            aces.append(parsed)
        pos += ace_size

    return owner_sid, aces


def _parse_ace(ace_type, ace_data):
    if len(ace_data) < 8:
        return None
    mask = struct.unpack_from('<I', ace_data, 4)[0]

    if ace_type in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
        sid_offset = 8
        sub_count = ace_data[sid_offset + 1] if sid_offset + 1 < len(ace_data) else 0
        sid_len = 8 + 4 * sub_count
        if sid_offset + sid_len > len(ace_data):
            return None
        sid = format_sid(ace_data[sid_offset:sid_offset + sid_len])
        return {
            'type': ace_type,
            'mask': mask,
            'object_type': None,
            'inherited_object_type': None,
            'sid': sid,
        }

    if ace_type in (ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE):
        if len(ace_data) < 12:
            return None
        flags = struct.unpack_from('<I', ace_data, 8)[0]
        offset = 12
        object_type = None
        inherited_object_type = None
        if flags & ACE_OBJECT_TYPE_PRESENT:
            if offset + 16 > len(ace_data):
                return None
            raw_guid = ace_data[offset:offset + 16]
            object_type = str(UUID(bytes_le=raw_guid)).lower()
            offset += 16
        if flags & 0x02:
            if offset + 16 > len(ace_data):
                return None
            raw_guid = ace_data[offset:offset + 16]
            inherited_object_type = str(UUID(bytes_le=raw_guid)).lower()
            offset += 16
        sub_count = ace_data[offset + 1] if offset + 1 < len(ace_data) else 0
        sid_len = 8 + 4 * sub_count
        if offset + sid_len > len(ace_data):
            return None
        sid = format_sid(ace_data[offset:offset + sid_len])
        return {
            'type': ace_type,
            'mask': mask,
            'object_type': object_type,
            'inherited_object_type': inherited_object_type,
            'sid': sid,
        }

    return None


def _resolve_sid(sid, session, domain_sid):
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    if domain_sid and sid.startswith(domain_sid + '-'):
        rid = int(sid.rsplit('-', 1)[1])
        if rid in DOMAIN_RELATIVE_SIDS:
            return '%s\\%s' % (session.domain.upper(), DOMAIN_RELATIVE_SIDS[rid])
    try:
        result = list(session.search(
            '(objectSid=%s)' % sid,
            ['sAMAccountName', 'objectClass'],
            search_base=session.base_dn))
        if result:
            name = result[0]['attributes'].get('sAMAccountName', sid)
            return '%s\\%s' % (session.domain.upper(), name)
    except Exception:
        pass
    return sid


def _has_reanimate(ace):
    if ace['type'] in (ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE):
        return False
    if ace['mask'] & GENERIC_ALL or ace['mask'] & ADS_RIGHT_GENERIC_ALL == ADS_RIGHT_GENERIC_ALL:
        return True
    if not (ace['mask'] & ADS_RIGHT_DS_CONTROL_ACCESS):
        return False
    if ace['object_type'] is None:
        return True
    return ace['object_type'] == REANIMATE_TOMBSTONES


def _has_list_contents(ace):
    if ace['type'] in (ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE):
        return False
    if ace['mask'] & GENERIC_ALL or ace['mask'] & ADS_RIGHT_GENERIC_ALL == ADS_RIGHT_GENERIC_ALL:
        return True
    return bool(ace['mask'] & ADS_RIGHT_DS_LIST_CONTENTS)


class AccessEnumerator:
    def __init__(self, session):
        self.session = session

    def enumerate(self):
        findings = []
        rb_info = self.session.get_recycle_bin_info()
        findings.append({
            'category': 'recycle_bin_status',
            'enabled': rb_info['enabled'],
            'tombstone_lifetime': rb_info['tombstone_lifetime'],
            'deleted_object_lifetime': rb_info['deleted_object_lifetime'],
        })

        domain_sid = self._get_domain_sid()

        reanimate_principals = self._check_reanimate_right(domain_sid)
        findings.append({
            'category': 'reanimate_tombstones',
            'description': 'Principals with the Reanimate Tombstones extended right on the domain object',
            'principals': reanimate_principals,
        })

        list_principals = self._check_deleted_objects_access(domain_sid)
        findings.append({
            'category': 'deleted_objects_access',
            'description': 'Principals with List Contents on the Deleted Objects container',
            'principals': list_principals,
        })

        return findings

    def _get_domain_sid(self):
        for entry in self.session.search(
                '(objectClass=domain)',
                ['objectSid'],
                search_base=self.session.base_dn,
                search_scope=BASE):
            sid = entry['attributes'].get('objectSid')
            if sid:
                return format_sid(sid) if isinstance(sid, bytes) else sid
        return None

    def _check_reanimate_right(self, domain_sid):
        principals = []
        sd_control = security_descriptor_control(sdflags=0x05)
        for entry in self.session.search(
                '(objectClass=domain)',
                ['nTSecurityDescriptor'],
                search_base=self.session.base_dn,
                search_scope=BASE,
                controls=sd_control):
            raw_sd = entry.get('raw_attributes', {}).get('nTSecurityDescriptor')
            if not raw_sd:
                raw_sd = entry.get('attributes', {}).get('nTSecurityDescriptor')
            if isinstance(raw_sd, list):
                raw_sd = raw_sd[0] if raw_sd else None
            if not raw_sd or not isinstance(raw_sd, bytes):
                logging.warning('Could not read domain security descriptor')
                return principals

            owner, aces = _parse_sd_dacl(raw_sd)
            for ace in aces:
                if _has_reanimate(ace):
                    name = _resolve_sid(ace['sid'], self.session, domain_sid)
                    principals.append({
                        'sid': ace['sid'],
                        'name': name,
                        'ace_type': 'ALLOW' if ace['type'] in (0x00, 0x05) else 'DENY',
                        'scope': 'all_control_access' if ace['object_type'] is None else 'reanimate_tombstones',
                    })
        return principals

    def _check_deleted_objects_access(self, domain_sid):
        principals = []
        deleted_dn = 'CN=Deleted Objects,%s' % self.session.base_dn
        sd_control = security_descriptor_control(sdflags=0x05)
        show_deleted = [(LDAP_SERVER_SHOW_DELETED_OID, True, None)]
        merged = list(sd_control) + show_deleted

        try:
            results = self.session.ldap.extend.standard.paged_search(
                deleted_dn,
                '(objectClass=*)',
                search_scope=BASE,
                attributes=['nTSecurityDescriptor'],
                controls=merged,
                paged_size=10,
                generator=False)
        except Exception as e:
            logging.warning('Could not read Deleted Objects container SD: %s', e)
            return principals

        for entry in results:
            if entry.get('type') != 'searchResEntry':
                continue
            raw_sd = entry.get('raw_attributes', {}).get('nTSecurityDescriptor')
            if isinstance(raw_sd, list):
                raw_sd = raw_sd[0] if raw_sd else None
            if not raw_sd or not isinstance(raw_sd, bytes):
                continue

            owner, aces = _parse_sd_dacl(raw_sd)
            if owner:
                name = _resolve_sid(owner, self.session, domain_sid)
                principals.append({
                    'sid': owner,
                    'name': name,
                    'right': 'OWNER',
                })
            for ace in aces:
                if _has_list_contents(ace):
                    name = _resolve_sid(ace['sid'], self.session, domain_sid)
                    principals.append({
                        'sid': ace['sid'],
                        'name': name,
                        'right': 'LIST_CONTENTS',
                        'ace_type': 'ALLOW' if ace['type'] in (0x00, 0x05) else 'DENY',
                    })
        return principals
