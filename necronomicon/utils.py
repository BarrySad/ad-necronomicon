import re
import struct


def domain2ldap(domain):
    return 'DC=' + ',DC='.join(str(domain).rstrip('.').split('.'))


def ldap2domain(ldap_dn):
    return re.sub(',DC=', '.', ldap_dn[ldap_dn.find('DC='):], flags=re.I)[3:]


def format_sid(sid_bytes):
    if isinstance(sid_bytes, str):
        return sid_bytes
    revision = sid_bytes[0]
    sub_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], 'big')
    subs = [struct.unpack_from('<I', sid_bytes, 8 + 4 * i)[0]
            for i in range(sub_count)]
    return 'S-%d-%d-%s' % (revision, authority, '-'.join(str(s) for s in subs))


def sid_to_bytes(sid_str):
    parts = sid_str.split('-')
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]
    buf = struct.pack('BB', revision, len(sub_authorities))
    buf += struct.pack('>Q', authority)[2:]
    for sa in sub_authorities:
        buf += struct.pack('<I', sa)
    return buf


def parse_guid(raw):
    if isinstance(raw, str):
        return raw.strip('{}').lower()
    if isinstance(raw, bytes) and len(raw) == 16:
        from uuid import UUID
        return str(UUID(bytes_le=raw))
    return str(raw)


WELL_KNOWN_SIDS = {
    'S-1-0-0': 'Nobody',
    'S-1-1-0': 'Everyone',
    'S-1-5-7': 'Anonymous Logon',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'LOCAL SYSTEM',
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
}


DOMAIN_RELATIVE_SIDS = {
    512: 'Domain Admins',
    516: 'Domain Controllers',
    518: 'Schema Admins',
    519: 'Enterprise Admins',
}
