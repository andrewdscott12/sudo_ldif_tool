#!/usr/bin/env python3
"""
sudo_ldif_validator.py - Validate sudoRole LDIF entries.

Validation checks:
- sudoUser values resolve to LDAP users/groups (with lookup cache)
- sudoCommand executables exist on the local system
- sudoOption syntax is valid and option names are recognized
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from ldap3 import ALL, Connection, Server
except Exception:  # pragma: no cover - optional dependency at runtime
    Connection = None
    Server = None
    ALL = None


USER_NAME_ATTRS = ("uid", "sAMAccountName", "cn")

# Known sudo LDAP option names used in sudoOption values.
KNOWN_LDAP_OPTION_NAMES = {
    "authenticate",
    "requiretty",
    "noexec",
    "setenv",
    "env_reset",
    "always_set_home",
    "set_home",
    "stay_setuid",
    "match_group_by_gid",
    "visiblepw",
    "env_editor",
    "rootpw",
    "runaspw",
    "targetpw",
    "log_input",
    "log_output",
    "use_pty",
    "mail_always",
    "mail_all_cmnds",
    "mail_no_user",
    "mail_no_host",
    "ignore_local_sudoers",
    "fqdn",
    "intercept",
    "follow",
    "ignore_iolog_errors",
    "ignore_logfile_errors",
    "verifypw",
    "listpw",
    "passwd_tries",
    "passwd_timeout",
    "timestamp_timeout",
    "timestamp_type",
    "lecture",
    "lecture_file",
    "badpass_message",
    "logfile",
    "syslog",
    "syslog_goodpri",
    "syslog_badpri",
    "closefrom",
    "runas_default",
    "umask",
    "umask_override",
    "secure_path",
    "editor",
    "iolog_dir",
    "iolog_file",
    "iolog_mode",
    "iolog_user",
    "iolog_group",
    "fdexec",
    "loglinelen",
    "pam_service",
    "pam_login_service",
    "sudoers_locale",
    "log_year",
    "maxseq",
    "exempt_group",
    "passprompt",
    "passprompt_override",
    "pwfeedback",
    "tty_tickets",
    "insults",
    "requiretty",
    "shell_noargs",
}


@dataclass
class LdifEntry:
    dn: str
    attributes: Dict[str, List[str]]


@dataclass
class EntryValidationResult:
    dn: str
    cn: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class LdapIdentityValidator:
    def __init__(
        self,
        server_uri: str,
        bind_dn: Optional[str],
        bind_password: Optional[str],
        search_base: str,
        user_attr: str = "uid",
    ) -> None:
        if not (server_uri and search_base):
            raise ValueError("--ldap-uri and --ldap-search-base are required for sudoUser validation")
        if not Server or not Connection:
            raise RuntimeError("ldap3 is not installed. Install dependencies from requirements.txt.")

        self._conn: Optional[Any] = None
        self._search_base = search_base
        self._user_attr = user_attr
        self._cache: Dict[str, Tuple[bool, Optional[str], str]] = {}

        server = Server(server_uri, get_info=ALL)
        self._conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=True,
            raise_exceptions=False,
        )
        if not self._conn.bound:
            raise RuntimeError("LDAP bind failed. Verify LDAP credentials and URL.")

    def close(self) -> None:
        if self._conn is not None and self._conn.bound:
            self._conn.unbind()

    def validate_sudo_user(self, raw_value: str) -> Tuple[bool, Optional[str], str]:
        value = raw_value.strip()
        if value in self._cache:
            return self._cache[value]

        original = value
        negated = value.startswith("!")
        if negated:
            value = value[1:].strip()

        if not value or value.upper() == "ALL":
            result = (True, "special", "special token")
            self._cache[original] = result
            return result

        if value.startswith("+"):
            result = (True, "netgroup", "netgroup reference not validated via LDAP user/group lookup")
            self._cache[original] = result
            return result

        if value.startswith("%"):
            group_name = value[1:].strip()
            group_exists = self._group_exists(group_name)
            if group_exists:
                result = (True, "group", "LDAP group found")
                self._cache[original] = result
                return result

            # If %name does not resolve as group, check if it is actually a user.
            user_exists = self._user_exists(group_name)
            if user_exists:
                suggested = self._with_negation(group_name, negated)
                result = (
                    False,
                    None,
                    (
                        f"LDAP group not found, but LDAP user '{group_name}' exists. "
                        f"Suggested fix: sudoUser '{suggested}'"
                    ),
                )
                self._cache[original] = result
                return result

            result = (False, None, "LDAP group not found")
            self._cache[original] = result
            return result

        # Numeric IDs can appear as #uid / #gid references.
        if value.startswith("#") and value[1:].isdigit():
            result = (True, "numeric", "numeric user/group ID reference")
            self._cache[original] = result
            return result

        user_exists = self._user_exists(value)
        if user_exists:
            result = (True, "user", "LDAP user found")
            self._cache[original] = result
            return result

        group_exists = self._group_exists(value)
        if group_exists:
            suggested = self._with_negation(f"%{value}", negated)
            result = (
                False,
                None,
                (
                    f"LDAP user not found, but LDAP group '{value}' exists. "
                    f"Suggested fix: sudoUser '{suggested}'"
                ),
            )
            self._cache[original] = result
            return result

        result = (False, None, "LDAP user/group not found")
        self._cache[original] = result
        return result

    @staticmethod
    def _with_negation(value: str, negated: bool) -> str:
        return f"!{value}" if negated else value

    def _user_exists(self, user_name: str) -> bool:
        escaped = ldap_filter_escape(user_name)
        filter_expr = (
            "(&(objectClass=person)(|"
            f"({self._user_attr}={escaped})"
            f"(uid={escaped})"
            f"(sAMAccountName={escaped})"
            f"(cn={escaped})"
            "))"
        )
        return self._search_one(filter_expr)

    def _group_exists(self, group_name: str) -> bool:
        escaped = ldap_filter_escape(group_name)
        strict_filter = (
            "(&(|"
            "(objectCategory=group)"  # Active Directory canonical group category
            "(objectClass=group)"  # Active Directory group object class
            "(objectClass=posixGroup)"
            "(objectClass=groupOfNames)"
            "(objectClass=groupOfUniqueNames)"
            ")(|"
            f"(cn={escaped})"
            f"(sAMAccountName={escaped})"
            f"(name={escaped})"  # Active Directory display/name attribute
            f"(gidNumber={escaped})"
            "))"
        )
        if self._search_one(strict_filter):
            return True

        # Fallback: some directories don't use canonical group classes.
        # Look up by name and infer group-likeness from objectClass/member attributes.
        fallback_filter = (
            "(|"
            f"(cn={escaped})"
            f"(sAMAccountName={escaped})"
            f"(name={escaped})"
            f"(gidNumber={escaped})"
            ")"
        )
        return self._search_group_like(fallback_filter)

    def _search_one(self, filter_expr: str) -> bool:
        assert self._conn is not None
        # Use no-attribute retrieval for existence checks. Requesting "dn" as an
        # attribute can fail on some LDAP servers (including AD) because DN is not
        # a regular attribute type.
        try:
            self._conn.search(
                search_base=self._search_base,
                search_filter=filter_expr,
                attributes=["1.1"],
                size_limit=1,
            )
        except Exception:
            # Fallback for servers that don't like 1.1 in this context.
            self._conn.search(
                search_base=self._search_base,
                search_filter=filter_expr,
                attributes=[],
                size_limit=1,
            )
        return bool(self._conn.entries)

    def _search_group_like(self, filter_expr: str) -> bool:
        assert self._conn is not None
        # Different LDAP schemas expose different group attributes. Try richer
        # attribute sets first, then degrade to broadly supported AD/OpenLDAP sets.
        attribute_sets = [
            ["objectClass", "member", "memberUid", "uniqueMember", "gidNumber", "distinguishedName"],
            ["objectClass", "member", "uniqueMember", "distinguishedName"],
            ["objectClass", "member", "distinguishedName"],
            ["objectClass"],
        ]

        searched = False
        for attrs in attribute_sets:
            try:
                self._conn.search(
                    search_base=self._search_base,
                    search_filter=filter_expr,
                    attributes=attrs,
                    size_limit=5,
                )
                searched = True
                break
            except Exception:
                continue

        if not searched:
            return False

        for entry in self._conn.entries:
            object_classes = [str(v).lower() for v in getattr(entry, "objectClass").values] if hasattr(entry, "objectClass") else []

            if any("group" in cls for cls in object_classes):
                return True

            if self._entry_has_values(entry, "member"):
                return True
            if self._entry_has_values(entry, "memberUid"):
                return True
            if self._entry_has_values(entry, "uniqueMember"):
                return True
            if self._entry_has_values(entry, "gidNumber"):
                return True

        return False

    @staticmethod
    def _entry_has_values(entry: Any, attr_name: str) -> bool:
        if not hasattr(entry, attr_name):
            return False
        values = getattr(entry, attr_name).values
        return bool(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate sudoRole LDIF entries against LDAP identities, local commands, "
            "and sudoOption syntax."
        )
    )
    parser.add_argument("input_ldif", help="Path to input LDIF file to validate")

    # Keep LDAP connection options aligned with sudo_to_ldif.py
    parser.add_argument("--ldap-uri", help="LDAP URI (e.g. ldaps://ldap.example.com)")
    parser.add_argument("--ldap-bind-dn", help="LDAP bind DN")
    parser.add_argument("--ldap-bind-password", help="LDAP bind password")
    parser.add_argument("--ldap-search-base", help="LDAP search base for groups/users")
    parser.add_argument(
        "--ldap-user-attr",
        default="uid",
        help="Preferred LDAP attribute to map user identity lookups (default: uid)",
    )

    parser.add_argument(
        "--strict-options",
        action="store_true",
        help="Treat unknown sudoOption names as errors instead of warnings",
    )
    return parser.parse_args()


def parse_ldif_file(path: Path) -> List[LdifEntry]:
    entries: List[LdifEntry] = []

    current_dn: Optional[str] = None
    current_attrs: Dict[str, List[str]] = {}
    prev_key: Optional[str] = None

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lines.append("")  # sentinel for flushing last entry

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")

        if not line:
            if current_dn is not None or current_attrs:
                entries.append(LdifEntry(dn=current_dn or "", attributes=current_attrs))
            current_dn = None
            current_attrs = {}
            prev_key = None
            continue

        if line.startswith("#"):
            continue

        if line.startswith(" "):
            continuation = line[1:]
            if prev_key == "dn" and current_dn is not None:
                current_dn += continuation
            elif prev_key and prev_key in current_attrs and current_attrs[prev_key]:
                current_attrs[prev_key][-1] += continuation
            continue

        if ":" not in line:
            prev_key = None
            continue

        key, value = line.split(":", 1)
        value = value.lstrip(" ")

        if key.lower() == "dn":
            current_dn = value
            prev_key = "dn"
            continue

        current_attrs.setdefault(key, []).append(value)
        prev_key = key

    return entries


def first_attr(entry: LdifEntry, name: str, default: str = "") -> str:
    values = entry.attributes.get(name, [])
    return values[0] if values else default


def is_sudo_role_entry(entry: LdifEntry) -> bool:
    classes = [c.lower() for c in entry.attributes.get("objectClass", [])]
    return "sudorole" in classes


def validate_sudo_option(option: str) -> Tuple[bool, Optional[str], Optional[str]]:
    token = option.strip()
    if not token:
        return False, "empty sudoOption value", None

    # LDAP schema values are option names with optional leading ! and optional =value.
    # Examples: authenticate, !requiretty, secure_path=/usr/sbin:/usr/bin
    if ":" in token:
        return False, f"invalid sudoOption syntax: {token}", None

    if not re.match(r"^!?[A-Za-z_][A-Za-z0-9_]*(?:=.+)?$", token):
        return False, f"invalid sudoOption syntax: {token}", None

    core = token.lstrip("!")
    option_name = core.split("=", 1)[0].lower()

    if option_name not in KNOWN_LDAP_OPTION_NAMES:
        return True, None, f"unknown sudoOption name: {option_name}"

    return True, None, None


def normalize_command_for_lookup(command: str) -> str:
    candidate = command.strip()
    if candidate.startswith("!"):
        candidate = candidate[1:].strip()

    # Strip digest prefixes like sha256:ABCD... before command path.
    candidate = re.sub(
        r"^(?:(?:sha(?:224|256|384|512)|md5):[A-Fa-f0-9]+\s+)+",
        "",
        candidate,
        flags=re.IGNORECASE,
    )
    return candidate


def extract_executable(command: str) -> Optional[str]:
    candidate = normalize_command_for_lookup(command)
    if not candidate or candidate.upper() == "ALL":
        return None

    try:
        tokens = shlex.split(candidate)
    except ValueError:
        tokens = candidate.split()

    if not tokens:
        return None
    return tokens[0]


def command_exists_on_system(command: str) -> Tuple[bool, str]:
    exe = extract_executable(command)
    if exe is None:
        return True, "special token"

    if any(ch in exe for ch in ["*", "?", "["]):
        matches = glob.glob(exe)
        for match in matches:
            if os.path.isfile(match) and os.access(match, os.X_OK):
                return True, f"matched executable path: {match}"
        return False, f"no executable matched command glob: {exe}"

    if os.path.isabs(exe):
        if not os.path.exists(exe):
            return False, f"command path does not exist: {exe}"
        if not os.path.isfile(exe):
            return False, f"command path is not a file: {exe}"
        if not os.access(exe, os.X_OK):
            return False, f"command path is not executable: {exe}"
        return True, "executable path exists"

    resolved = shutil.which(exe)
    if resolved:
        return True, f"resolved on PATH: {resolved}"
    return False, f"command not found on PATH: {exe}"


def validate_entry(
    entry: LdifEntry,
    ldap_validator: LdapIdentityValidator,
    strict_options: bool,
) -> EntryValidationResult:
    cn = first_attr(entry, "cn", default="<missing-cn>")
    result = EntryValidationResult(dn=entry.dn, cn=cn)

    sudo_users = entry.attributes.get("sudoUser", [])
    if not sudo_users:
        result.errors.append("missing sudoUser")
    for value in sudo_users:
        valid, identity_type, detail = ldap_validator.validate_sudo_user(value)
        if not valid:
            result.errors.append(f"sudoUser '{value}' invalid: {detail}")
        elif identity_type == "netgroup":
            result.warnings.append(f"sudoUser '{value}' not fully validated: {detail}")

    sudo_commands = entry.attributes.get("sudoCommand", [])
    if not sudo_commands:
        result.errors.append("missing sudoCommand")
    for command in sudo_commands:
        ok, detail = command_exists_on_system(command)
        if not ok:
            result.errors.append(f"sudoCommand '{command}' invalid: {detail}")

    sudo_options = entry.attributes.get("sudoOption", [])
    for option in sudo_options:
        valid, error_text, warning_text = validate_sudo_option(option)
        if not valid and error_text:
            result.errors.append(error_text)
        elif warning_text:
            if strict_options:
                result.errors.append(warning_text)
            else:
                result.warnings.append(warning_text)

    return result


def ldap_filter_escape(value: str) -> str:
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    out = []
    for ch in value:
        out.append(replacements.get(ch, ch))
    return "".join(out)


def main() -> None:
    args = parse_args()

    input_ldif = Path(args.input_ldif)
    if not input_ldif.exists():
        print(f"ERROR: Input LDIF not found: {input_ldif}", file=sys.stderr)
        sys.exit(1)

    try:
        ldap_validator = LdapIdentityValidator(
            server_uri=args.ldap_uri or "",
            bind_dn=args.ldap_bind_dn,
            bind_password=args.ldap_bind_password,
            search_base=args.ldap_search_base or "",
            user_attr=args.ldap_user_attr,
        )
    except Exception as exc:
        print(f"ERROR: Failed to initialize LDAP validator: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        entries = parse_ldif_file(input_ldif)
        sudo_entries = [entry for entry in entries if is_sudo_role_entry(entry)]

        if not sudo_entries:
            print(f"ERROR: No sudoRole entries found in {input_ldif}", file=sys.stderr)
            sys.exit(3)

        results = [validate_entry(entry, ldap_validator, args.strict_options) for entry in sudo_entries]
    finally:
        ldap_validator.close()

    total_errors = 0
    total_warnings = 0

    for result in results:
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] cn={result.cn} dn={result.dn}")

        for err in result.errors:
            print(f"  ERROR: {err}")
        for warn in result.warnings:
            print(f"  WARN: {warn}")

        total_errors += len(result.errors)
        total_warnings += len(result.warnings)

    print(
        f"\nValidated {len(results)} sudoRole entries: "
        f"{total_errors} error(s), {total_warnings} warning(s)."
    )

    if total_errors:
        sys.exit(4)


if __name__ == "__main__":
    main()
