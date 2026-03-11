# sudo_to_ldif

Convert CSV sudo policy reports into consolidated LDAP `sudoRole` LDIF entries.

## What This Script Does

The script ingests rows like:

`hostname,user|group,username|groupname,policyfile,sudo policy line`

Then it:

- Parses sudo policy lines into `sudoRunAsUser`, `sudoOption`, and `sudoCommand`
- Resolves AD group members (optional) and emits users as `sudoUser`
- Forces all `sudoUser` values to lowercase in output
- Consolidates policies into roles based on policy file name
- Applies special handling for `/etc/sudoers`

## Consolidation Rules

### 1) Non-`/etc/sudoers` policy files

Consolidation key is the policy file basename:

- `/etc/sudoers.d/G_VAS_SCANS` -> role `SUDO_G_VAS_SCANS`
- `/etc/sudoers.d/unixadmins` -> role `SUDO_unixadmins`

All matching rows for that file are merged into one role containing:

- combined `sudoUser`
- combined `sudoCommand`
- combined `sudoRunAsUser`
- combined `sudoOption`
- combined `sudoHost` (or `ALL` if threshold exceeded)

### 2) `/etc/sudoers` policy rows

- Shared signatures appearing on multiple hosts are consolidated into `SUDO_sudoers`
- One-off signatures found on only one host are emitted as:
  - `SUDO_suders_<hostname>`

Example:

- one-off on `app01` -> `SUDO_suders_app01`

## Active Directory Group Expansion

When LDAP args are provided, group rows are expanded to user members.

### Group lookup

Groups are searched as AD groups only:

- `objectClass=group`
- `cn=<group>` or `sAMAccountName=<group>`

### Membership source

- Uses `member` attribute (DN list)
- Each member DN is resolved to a username using preferred attr order:
  - `--ldap-user-attr` (default `uid`)
  - fallback: `uid`, `sAMAccountName`, `cn`

If group resolution returns no members, script falls back to the original subject value.

## Base DN Configuration

You have two ways to set the target base DN for generated roles.

### Option A: Script default at top of file

In `sudo_to_ldif.py`, edit:

```python
SUDO_BASE_DN = "ou=SUDOers,dc=example,dc=com"
```

### Option B: CLI override (recommended per run)

```bash
python3 sudo_to_ldif.py input.csv output.ldif \
  --base-dn "ou=SUDOers,dc=mycompany,dc=com"
```

## CLI Usage

```bash
python3 sudo_to_ldif.py SOURCE_CSV OUTPUT_LDIF [options]
```

### Required args

- `SOURCE_CSV`
- `OUTPUT_LDIF`

### Options

- `--base-dn <dn>`: output base DN for role DNs
- `--host-all-threshold <n>`: if hosts > n, emit `sudoHost: ALL` (default 25)
- `--ldap-uri <uri>`
- `--ldap-bind-dn <bind_dn>`
- `--ldap-bind-password <password>`
- `--ldap-search-base <search_base>`
- `--ldap-user-attr <attr>`

## LDAP Server and Credentials Example

```bash
python3 sudo_to_ldif.py policies.csv output.ldif \
  --base-dn "ou=SUDOers,dc=corp,dc=local" \
  --ldap-uri "ldaps://dc01.corp.local" \
  --ldap-bind-dn "cn=ldap-reader,ou=Service Accounts,dc=corp,dc=local" \
  --ldap-bind-password "REDACTED" \
  --ldap-search-base "dc=corp,dc=local" \
  --ldap-user-attr "sAMAccountName"
```

## Sudo Option Translation

The parser translates these into LDAP-style `sudoOption` values:

- `NOPASSWD:` -> `!authenticate`
- `PASSWD:` -> `authenticate`
- `NOEXEC:` -> `noexec`
- `EXEC:` -> `!noexec`
- `SETENV:` -> `setenv`
- `NOSETENV:` -> `!setenv`

## Notes

- Lines beginning with `###` are ignored.
- Header lines are ignored.
- 4-column and 5-column report variants are supported.
- Output DNs use `cn=<role_name>,<base_dn>`.
