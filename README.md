# sudo_to_ldif - Sudo Policy CSV to LDIF Converter

A Python tool that converts CSV-formatted sudo policy reports into consolidated LDAP LDIF format for bulk import to a directory server.

## Overview

This tool reads CSV reports containing sudo policy lines from multiple servers and intelligently consolidates them into LDAP `sudoRole` objects. It automatically:

- **Consolidates policies** across multiple servers with identical rules
- **Merges commands** when the same users/groups have multiple sudo commands on the same hosts
- **Simplifies host lists** by using `sudoHost: ALL` when policies appear on many servers
- **Expands LDAP groups** to individual user members (optional)
- **Translates sudo options** to proper LDIF format (e.g., `NOPASSWD:` → `!authenticate`)
- **Handles edge cases** like comment lines, varied CSV column formats, and special characters

## Installation

### Requirements

- Python 3.7 or later
- `ldap3` library (for LDAP group expansion feature)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install 'ldap3>=2.9'
```

## Basic Usage

### Simple Conversion (No LDAP Lookup)

```bash
python3 sudo_to_ldif.py input.csv output.ldif
```

This reads the CSV file and generates LDIF without expanding groups to individual users.

### With Custom Base DN

The default base DN is `ou=SUDOers,dc=example,dc=com`. To specify a different base DN:

```bash
python3 sudo_to_ldif.py input.csv output.ldif \
  --base-dn "ou=SUDOers,dc=mycompany,dc=com"
```

You can also edit the `SUDO_BASE_DN` constant at the top of `sudo_to_ldif.py` (line 27):

```python
# Base DN for generated sudoRole objects.
SUDO_BASE_DN = "ou=SUDOers,dc=mycompany,dc=com"
```

### With LDAP Group Expansion

To resolve group names to individual LDAP user members:

```bash
python3 sudo_to_ldif.py input.csv output.ldif \
  --ldap-uri ldaps://ldap.example.com \
  --ldap-bind-dn "cn=serviceuser,ou=Service,dc=example,dc=com" \
  --ldap-bind-password "your_password" \
  --ldap-search-base "dc=example,dc=com"
```

**LDAP Connection Options:**

- `--ldap-uri`: LDAP server URI (e.g., `ldaps://ldap.example.com` or `ldap://ldap.example.com:389`)
- `--ldap-bind-dn`: DN for binding to LDAP (service account with read access)
- `--ldap-bind-password`: Password for the bind DN
- `--ldap-search-base`: Base DN to search for groups and users
- `--ldap-user-attr`: Attribute to extract from user objects (default: `uid`)

**How Group Expansion Works:**

1. For each group in the CSV (e.g., `G_VAS_UNIX_Admins`), the script searches LDAP for a matching group by:
   - `cn` (common name)
   - `sAMAccountName` (Active Directory)
   - `gidNumber` (POSIX groups)

2. It reads group membership from:
   - `memberUid` attributes (POSIX groups) → used directly as usernames
   - `member` or `uniqueMember` attributes (DN-based) → resolved to usernames

3. For DN-based members, it looks up each user and extracts the username from the preferred attribute (default: `uid`, also tries `sAMAccountName`, `cn`)

4. All resolved usernames are added as `sudoUser:` entries in the LDIF

**Without LDAP credentials**, group names are preserved as-is in the output (e.g., `sudoUser: G_VAS_UNIX_Admins`).

### Host Consolidation Threshold

When a policy appears on more than N servers, use `sudoHost: ALL` instead of listing each server:

```bash
python3 sudo_to_ldif.py input.csv output.ldif --host-all-threshold 25
```

Default threshold is 25 hosts.

## Input CSV Format

The tool expects CSV data with the following columns:

```
hostname,user|group,username|groupname,policyfile,sudo policy line
```

**Example:**

```csv
awsa04lts557,user,root,/etc/sudoers,root ALL=(ALL) ALL
awsa04lts557,group,wheel,/etc/sudoers,%wheel ALL=(ALL) ALL
awsa04lts60,user,root,/etc/sudoers,root ALL=(ALL) ALL
awsa04lts60,group,G_VAS_Admins,/etc/sudoers.d/admins,%G_VAS_Admins ALL=(ALL) NOPASSWD: ALL
```

**CSV Column Details:**

1. **hostname**: Server where the policy was found
2. **user|group**: Type indicator (`user` or `group`)
3. **username|groupname**: The user or group name the policy applies to
4. **policyfile**: Source file (e.g., `/etc/sudoers`, `/etc/sudoers.d/admins`)
5. **sudo policy line**: The actual sudo rule (can contain commas)

**Special Handling:**

- Lines starting with `###` are treated as comments and ignored
- Header lines starting with `hostname,user|group` are skipped
- 4-column CSV rows where column 4 contains `filepath:rule` are automatically split

## Output LDIF Format

Generated LDIF entries follow this structure:

```ldif
dn: cn=SUDO_<command>,ou=SUDOers,dc=example,dc=com
objectClass: top
objectClass: sudoRole
cn: SUDO_<command>
sudoUser: <username>
sudoHost: <hostname>
sudoRunAsUser: <runas_user>
sudoOption: <option>
sudoCommand: <command>
description: source_files=<original_files>
```

**CN Generation:**

- Format: `cn=SUDO_<first_command_sanitized>`
- Collision handling: `SUDO_ALL`, `SUDO_ALL_2`, `SUDO_ALL_3`, etc.
- Command names are sanitized (alphanumeric, dots, dashes, underscores only)

**Sudo Option Translation:**

The script automatically translates sudo option tokens to LDIF format:

| Sudo Token | LDIF sudoOption |
|------------|----------------|
| `NOPASSWD:` | `!authenticate` |
| `PASSWD:` | `authenticate` |
| `NOEXEC:` | `noexec` |
| `EXEC:` | `!noexec` |
| `SETENV:` | `setenv` |
| `NOSETENV:` | `!setenv` |

## How Consolidation Works

The script intelligently consolidates policies based on several factors:

### 1. Same Policy, Multiple Hosts

**Input:**
```csv
server1,user,alice,/etc/sudoers,alice ALL=(ALL) /usr/bin/systemctl
server2,user,alice,/etc/sudoers,alice ALL=(ALL) /usr/bin/systemctl
server3,user,alice,/etc/sudoers,alice ALL=(ALL) /usr/bin/systemctl
```

**Output (one sudoRole):**
```ldif
dn: cn=SUDO__usr_bin_systemctl,ou=SUDOers,dc=example,dc=com
objectClass: top
objectClass: sudoRole
cn: SUDO__usr_bin_systemctl
sudoUser: alice
sudoHost: server1
sudoHost: server2
sudoHost: server3
sudoRunAsUser: ALL
sudoCommand: /usr/bin/systemctl
```

### 2. Multiple Commands Merged

**Input:**
```csv
server1,user,bob,/etc/sudoers,bob ALL=(ALL) /bin/ls
server1,user,bob,/etc/sudoers,bob ALL=(ALL) /bin/cat
server1,user,bob,/etc/sudoers,bob ALL=(ALL) /usr/bin/vim
```

**Output (one sudoRole with multiple commands):**
```ldif
dn: cn=SUDO__bin_cat,ou=SUDOers,dc=example,dc=com
objectClass: top
objectClass: sudoRole
cn: SUDO__bin_cat
sudoUser: bob
sudoHost: server1
sudoRunAsUser: ALL
sudoCommand: /bin/cat
sudoCommand: /bin/ls
sudoCommand: /usr/bin/vim
```

### 3. Host Threshold

**Input (30 servers):**
```csv
server01,user,root,/etc/sudoers,root ALL=(ALL) ALL
server02,user,root,/etc/sudoers,root ALL=(ALL) ALL
...
server30,user,root,/etc/sudoers,root ALL=(ALL) ALL
```

**Output (with --host-all-threshold 25):**
```ldif
dn: cn=SUDO_ALL,ou=SUDOers,dc=example,dc=com
objectClass: top
objectClass: sudoRole
cn: SUDO_ALL
sudoUser: root
sudoHost: ALL
sudoRunAsUser: ALL
sudoCommand: ALL
```

### Consolidation Key

Policies are consolidated when they share the same:
- Subject (user or group name)
- Host specification from sudo rule (e.g., `ALL`)
- Run-as users (e.g., `(ALL)`, `(root)`)
- Sudo options (e.g., `NOPASSWD:`)

Different commands are merged into the same `sudoRole` if everything else matches.

## Complete Example

```bash
# Basic conversion
python3 sudo_to_ldif.py policies.csv output.ldif

# With custom base DN and host threshold
python3 sudo_to_ldif.py policies.csv output.ldif \
  --base-dn "ou=SUDOers,dc=corp,dc=local" \
  --host-all-threshold 50

# With LDAP group expansion
python3 sudo_to_ldif.py policies.csv output.ldif \
  --base-dn "ou=SUDOers,dc=corp,dc=local" \
  --ldap-uri ldaps://dc01.corp.local \
  --ldap-bind-dn "cn=ldap-reader,ou=Services,dc=corp,dc=local" \
  --ldap-bind-password "SecurePassword123" \
  --ldap-search-base "dc=corp,dc=local" \
  --ldap-user-attr uid
```

## Importing to LDAP

Once the LDIF is generated, import it to your LDAP directory:

```bash
# OpenLDAP
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f output.ldif

# Or with ldapmodify
ldapmodify -a -x -D "cn=admin,dc=example,dc=com" -W -f output.ldif
```

## Troubleshooting

### LDAP Connection Issues

If LDAP group expansion fails:
1. Verify LDAP URI is correct (`ldaps://` for SSL/TLS)
2. Check bind DN has read permissions on group objects
3. Ensure search base encompasses your groups and users
4. Test connection manually: `ldapsearch -x -H ldaps://server -D "cn=user" -W -b "dc=example,dc=com" "(cn=groupname)"`

### Common Errors

**"Import ldap3 could not be resolved"**: Install ldap3 with `pip install ldap3`

**"Source CSV not found"**: Check file path is correct

**"LDAP bind failed"**: Verify credentials and LDAP server accessibility

## Script Configuration

Edit these constants at the top of `sudo_to_ldif.py` to change defaults:

```python
# Base DN for generated sudoRole objects (line 27)
SUDO_BASE_DN = "ou=SUDOers,dc=example,dc=com"

# Default host threshold (line 29)
DEFAULT_HOST_ALL_THRESHOLD = 25

# LDAP group member attributes to check (line 30)
GROUP_MEMBER_ATTRS = ("memberUid", "member", "uniqueMember")

# User attribute preferences for username extraction (line 31)
USER_NAME_ATTRS = ("uid", "sAMAccountName", "cn")
```

## License

This tool is provided as-is for administrative use.
