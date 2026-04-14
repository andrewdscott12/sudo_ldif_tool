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
import difflib
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

TAG_TO_LDAP_OPTION = {
    "NOPASSWD": "!authenticate",
    "PASSWD": "authenticate",
    "NOEXEC": "noexec",
    "EXEC": "!noexec",
    "SETENV": "setenv",
    "NOSETENV": "!setenv",
    "LOG_INPUT": "log_input",
    "NOLOG_INPUT": "!log_input",
    "LOG_OUTPUT": "log_output",
    "NOLOG_OUTPUT": "!log_output",
    "FOLLOW": "follow",
    "NOFOLLOW": "!follow",
    "INTERCEPT": "intercept",
    "NOINTERCEPT": "!intercept",
    "MAIL": "mail_all_cmnds",
    "NOMAIL": "!mail_all_cmnds",
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
        verbose: bool = False,
    ) -> None:
        if not (server_uri and search_base):
            raise ValueError("--ldap-uri and --ldap-search-base are required for sudoUser validation")
        if not Server or not Connection:
            raise RuntimeError("ldap3 is not installed. Install dependencies from requirements.txt.")

        self._conn: Optional[Any] = None
        self._search_base = search_base
        self._user_attr = user_attr
        self._verbose = verbose
        self._cache: Dict[str, Tuple[bool, Optional[str], str]] = {}
        self._user_exists_cache: Dict[str, bool] = {}
        self._group_exists_cache: Dict[str, bool] = {}
        self._search_cache: Dict[str, bool] = {}

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

    def _candidate_user_attrs(self) -> List[str]:
        # Keep this list short and index-friendly for large directories.
        # We intentionally avoid broad CN lookups unless needed because they tend
        # to be slower and can match many non-login objects.
        attrs = [self._user_attr, "sAMAccountName", "uid", "userPrincipalName"]
        unique: List[str] = []
        for attr in attrs:
            if attr and attr not in unique:
                unique.append(attr)
        return unique

    def close(self) -> None:
        if self._conn is not None and self._conn.bound:
            self._conn.unbind()

    def _vlog(self, message: str) -> None:
        if self._verbose:
            print(f"[verbose] {message}", file=sys.stderr, flush=True)

    def validate_sudo_user(self, raw_value: str) -> Tuple[bool, Optional[str], str]:
        value = raw_value.strip()
        cache_key = value.casefold()
        if cache_key in self._cache:
            self._vlog(f"sudoUser cache hit for '{raw_value}'")
            return self._cache[cache_key]

        self._vlog(f"sudoUser evaluate '{raw_value}'")

        original = value
        negated = value.startswith("!")
        if negated:
            value = value[1:].strip()

        if not value or value.upper() == "ALL":
            result = (True, "special", "special token")
            self._cache[cache_key] = result
            return result

        if value.startswith("+"):
            result = (True, "netgroup", "netgroup reference not validated via LDAP user/group lookup")
            self._cache[cache_key] = result
            return result

        if value.startswith("%"):
            group_name = value[1:].strip()
            group_exists = self._group_exists(group_name)
            if group_exists:
                result = (True, "group", "LDAP group found")
                self._cache[cache_key] = result
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
                self._cache[cache_key] = result
                return result

            result = (False, None, "LDAP group not found")
            self._cache[cache_key] = result
            return result

        # Numeric IDs can appear as #uid / #gid references.
        if value.startswith("#") and value[1:].isdigit():
            result = (True, "numeric", "numeric user/group ID reference")
            self._cache[cache_key] = result
            return result

        user_exists = self._user_exists(value)
        if user_exists:
            result = (True, "user", "LDAP user found")
            self._cache[cache_key] = result
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
            self._cache[cache_key] = result
            return result

        result = (False, None, "LDAP user/group not found")
        self._cache[cache_key] = result
        return result

    @staticmethod
    def _with_negation(value: str, negated: bool) -> str:
        return f"!{value}" if negated else value

    def suggest_sudo_user_fix(self, raw_value: str) -> Optional[str]:
        value = raw_value.strip()
        if not value:
            return None

        negated = value.startswith("!")
        core = value[1:].strip() if negated else value

        if not core or core.upper() == "ALL" or core.startswith("+"):
            return None
        if core.startswith("#") and core[1:].isdigit():
            return None

        if core.startswith("%"):
            group_name = core[1:].strip()
            if not group_name:
                return None
            if not self._group_exists(group_name) and self._user_exists(group_name):
                return self._with_negation(group_name, negated)
            return None

        if not self._user_exists(core) and self._group_exists(core):
            return self._with_negation(f"%{core}", negated)

        return None

    def _user_exists(self, user_name: str) -> bool:
        key = user_name.strip().casefold()
        if key in self._user_exists_cache:
            self._vlog(f"user-exists cache hit for '{user_name}' -> {self._user_exists_cache[key]}")
            return self._user_exists_cache[key]

        escaped = ldap_filter_escape(user_name)
        exists = False
        for attr in self._candidate_user_attrs():
            # Use one exact attribute at a time to improve index usage on LDAP servers.
            filter_expr = (
                "(&(|"
                "(objectClass=user)"
                "(objectClass=person)"
                "(objectClass=posixAccount)"
                f")({attr}={escaped}))"
            )
            if self._search_one(filter_expr):
                exists = True
                self._vlog(f"user-exists ldap search for '{user_name}' matched on {attr}")
                break

        if not exists:
            self._vlog(f"user-exists ldap search for '{user_name}' -> False")

        self._user_exists_cache[key] = exists
        return exists

    def _group_exists(self, group_name: str) -> bool:
        key = group_name.strip().casefold()
        if key in self._group_exists_cache:
            self._vlog(f"group-exists cache hit for '{group_name}' -> {self._group_exists_cache[key]}")
            return self._group_exists_cache[key]

        escaped = ldap_filter_escape(group_name)
        name_matchers = [
            f"(cn={escaped})",
            f"(sAMAccountName={escaped})",
            f"(name={escaped})",  # Active Directory display/name attribute
        ]
        if group_name.isdigit():
            name_matchers.append(f"(gidNumber={escaped})")

        name_filter = "(|" + "".join(name_matchers) + ")"

        strict_filter = (
            "(&(|"
            "(objectCategory=group)"  # Active Directory canonical group category
            "(objectClass=group)"  # Active Directory group object class
            "(objectClass=posixGroup)"
            ")"
            f"{name_filter}"
            ")"
        )
        if self._search_one(strict_filter):
            self._vlog(f"group-exists strict search for '{group_name}' -> True")
            self._group_exists_cache[key] = True
            return True

        # Fallback: some directories don't use canonical group classes.
        # Look up by name and infer group-likeness from objectClass/member attributes.
        fallback_filter = name_filter
        exists = self._search_group_like(fallback_filter)
        self._vlog(f"group-exists fallback search for '{group_name}' -> {exists}")
        self._group_exists_cache[key] = exists
        return exists

    def _search_one(self, filter_expr: str) -> bool:
        if filter_expr in self._search_cache:
            self._vlog("ldap search cache hit")
            return self._search_cache[filter_expr]

        assert self._conn is not None
        # Use no-attribute retrieval for existence checks. Requesting "dn" as an
        # attribute can fail on some LDAP servers (including AD) because DN is not
        # a regular attribute type.
        try:
            self._vlog("ldap search execute (attributes=1.1)")
            self._conn.search(
                search_base=self._search_base,
                search_filter=filter_expr,
                attributes=["1.1"],
                size_limit=1,
            )
        except Exception:
            # Fallback for servers that don't like 1.1 in this context.
            self._vlog("ldap search retry (attributes=[]) after 1.1 failure")
            self._conn.search(
                search_base=self._search_base,
                search_filter=filter_expr,
                attributes=[],
                size_limit=1,
            )
        exists = bool(self._conn.entries)
        self._search_cache[filter_expr] = exists
        return exists

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
                self._vlog(f"group-like search execute (attributes={attrs})")
                self._conn.search(
                    search_base=self._search_base,
                    search_filter=filter_expr,
                    attributes=attrs,
                    size_limit=5,
                )
                searched = True
                break
            except Exception:
                self._vlog(f"group-like search attribute set failed: {attrs}")
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
    parser.add_argument(
        "--output-patch",
        nargs="?",
        const="",
        metavar="PATCH_FILE",
        help=(
            "Generate a unified diff patch that fixes sudoUser marker confusion, "
            "corrects/removes invalid sudoOption values, and removes invalid sudoCommand values. "
            "If PATCH_FILE is omitted, defaults to <input_ldif>.patch."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress to stderr for each value examined and LDAP lookup activity.",
    )
    parser.add_argument(
        "--verbose-ldap-only",
        action="store_true",
        help="Print only LDAP/cache lookup diagnostics to stderr (less noisy than --verbose).",
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


def canonicalize_sudo_option_for_patch(option: str) -> Optional[str]:
    token = option.strip()
    if not token:
        return None

    raw = token.rstrip(":")
    core = raw.lstrip("!")

    # Convert legacy tag syntax (e.g. NOPASSWD:) when possible.
    mapped = TAG_TO_LDAP_OPTION.get(core.upper())
    if mapped:
        if raw.startswith("!") and not mapped.startswith("!"):
            return f"!{mapped}"
        return mapped

    # Convert NO<option> forms into !option if recognized.
    upper = core.upper()
    if upper.startswith("NO"):
        candidate = upper[2:].lower()
        if candidate in KNOWN_LDAP_OPTION_NAMES:
            return f"!{candidate}"

    # Normalize plain forms.
    if raw.startswith("!"):
        candidate = raw[1:]
        if "=" in candidate:
            key, value = candidate.split("=", 1)
            if key.lower() in KNOWN_LDAP_OPTION_NAMES:
                return f"!{key.lower()}={value}"
            return None
        if candidate.lower() in KNOWN_LDAP_OPTION_NAMES:
            return f"!{candidate.lower()}"
        return None

    if "=" in raw:
        key, value = raw.split("=", 1)
        if key.lower() in KNOWN_LDAP_OPTION_NAMES:
            return f"{key.lower()}={value}"
        return None

    lowered = raw.lower()
    if lowered in KNOWN_LDAP_OPTION_NAMES:
        return lowered

    # Syntax or schema unknown: remove from patch output.
    return None


def build_patch_fixed_entries(
    entries: List[LdifEntry],
    ldap_validator: LdapIdentityValidator,
) -> Tuple[List[LdifEntry], int, int, int]:
    fixed_entries: List[LdifEntry] = []
    user_fixes = 0
    option_fixes = 0
    command_fixes = 0

    for entry in entries:
        # Copy attribute lists so we can mutate without touching parsed originals.
        attrs = {k: list(v) for k, v in entry.attributes.items()}

        # Fix sudoUser marker confusion.
        if "sudoUser" in attrs:
            new_users: List[str] = []
            for sudo_user in attrs["sudoUser"]:
                suggestion = ldap_validator.suggest_sudo_user_fix(sudo_user)
                if suggestion and suggestion != sudo_user:
                    new_users.append(suggestion)
                    user_fixes += 1
                else:
                    new_users.append(sudo_user)
            attrs["sudoUser"] = _dedupe_preserve_order(new_users)

        # Correct or remove invalid sudoOption values.
        if "sudoOption" in attrs:
            new_opts: List[str] = []
            for opt in attrs["sudoOption"]:
                fixed_opt = canonicalize_sudo_option_for_patch(opt)
                if fixed_opt is None:
                    option_fixes += 1
                    continue
                if fixed_opt != opt:
                    option_fixes += 1
                new_opts.append(fixed_opt)
            attrs["sudoOption"] = _dedupe_preserve_order(new_opts)

        # Remove invalid sudoCommand values.
        if "sudoCommand" in attrs:
            new_cmds: List[str] = []
            for cmd in attrs["sudoCommand"]:
                ok, _detail = command_exists_on_system(cmd)
                if ok:
                    new_cmds.append(cmd)
                else:
                    command_fixes += 1
            attrs["sudoCommand"] = _dedupe_preserve_order(new_cmds)

        fixed_entries.append(LdifEntry(dn=entry.dn, attributes=attrs))

    return fixed_entries, user_fixes, option_fixes, command_fixes


def merge_fixed_sudo_entries(
    all_entries: List[LdifEntry],
    fixed_sudo_entries: List[LdifEntry],
) -> List[LdifEntry]:
    merged: List[LdifEntry] = []
    fixed_idx = 0
    for entry in all_entries:
        if is_sudo_role_entry(entry):
            merged.append(fixed_sudo_entries[fixed_idx])
            fixed_idx += 1
        else:
            merged.append(entry)
    return merged


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def render_ldif(entries: List[LdifEntry]) -> str:
    lines: List[str] = []
    for entry in entries:
        lines.append(f"dn: {entry.dn}")
        for key, values in entry.attributes.items():
            if key.lower() == "dn":
                continue
            for value in values:
                lines.append(f"{key}: {value}")
        lines.append("")
    return "\n".join(lines)


def resolve_patch_path(input_ldif: Path, patch_arg: Optional[str]) -> Path:
    if patch_arg is None:
        raise ValueError("patch_arg must not be None")
    if patch_arg.strip():
        return Path(patch_arg).expanduser().resolve()
    return input_ldif.with_suffix(input_ldif.suffix + ".patch")


def write_ldif_patch(input_ldif: Path, original_text: str, fixed_text: str, patch_path: Path) -> bool:
    diff_lines = list(
        difflib.unified_diff(
            original_text.splitlines(keepends=True),
            fixed_text.splitlines(keepends=True),
            fromfile=str(input_ldif),
            tofile=str(input_ldif),
        )
    )
    if not diff_lines:
        return False

    patch_path.write_text("".join(diff_lines), encoding="utf-8")
    return True


def validate_entry(
    entry: LdifEntry,
    ldap_validator: LdapIdentityValidator,
    strict_options: bool,
    verbose: bool = False,
) -> EntryValidationResult:
    cn = first_attr(entry, "cn", default="<missing-cn>")
    result = EntryValidationResult(dn=entry.dn, cn=cn)

    sudo_users = entry.attributes.get("sudoUser", [])
    if not sudo_users:
        result.errors.append("missing sudoUser")
    for value in sudo_users:
        if verbose:
            print(f"[verbose]   sudoUser check: {value}", file=sys.stderr, flush=True)
        valid, identity_type, detail = ldap_validator.validate_sudo_user(value)
        if verbose:
            print(
                f"[verbose]   sudoUser result: value={value} valid={valid} type={identity_type} detail={detail}",
                file=sys.stderr,
                flush=True,
            )
        if not valid:
            result.errors.append(f"sudoUser '{value}' invalid: {detail}")
        elif identity_type == "netgroup":
            result.warnings.append(f"sudoUser '{value}' not fully validated: {detail}")

    sudo_commands = entry.attributes.get("sudoCommand", [])
    if not sudo_commands:
        result.errors.append("missing sudoCommand")
    for command in sudo_commands:
        if verbose:
            print(f"[verbose]   sudoCommand check: {command}", file=sys.stderr, flush=True)
        ok, detail = command_exists_on_system(command)
        if verbose:
            print(
                f"[verbose]   sudoCommand result: command={command} valid={ok} detail={detail}",
                file=sys.stderr,
                flush=True,
            )
        if not ok:
            result.errors.append(f"sudoCommand '{command}' invalid: {detail}")

    sudo_options = entry.attributes.get("sudoOption", [])
    for option in sudo_options:
        if verbose:
            print(f"[verbose]   sudoOption check: {option}", file=sys.stderr, flush=True)
        valid, error_text, warning_text = validate_sudo_option(option)
        if verbose:
            print(
                f"[verbose]   sudoOption result: option={option} valid={valid} error={error_text} warning={warning_text}",
                file=sys.stderr,
                flush=True,
            )
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

    ldap_verbose = args.verbose or args.verbose_ldap_only
    item_verbose = args.verbose and (not args.verbose_ldap_only)

    input_ldif = Path(args.input_ldif)
    if not input_ldif.exists():
        print(f"ERROR: Input LDIF not found: {input_ldif}", file=sys.stderr)
        sys.exit(1)

    original_ldif_text = input_ldif.read_text(encoding="utf-8", errors="replace")

    try:
        ldap_validator = LdapIdentityValidator(
            server_uri=args.ldap_uri or "",
            bind_dn=args.ldap_bind_dn,
            bind_password=args.ldap_bind_password,
            search_base=args.ldap_search_base or "",
            user_attr=args.ldap_user_attr,
            verbose=ldap_verbose,
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

        results: List[EntryValidationResult] = []
        total = len(sudo_entries)
        for idx, entry in enumerate(sudo_entries, start=1):
            cn = first_attr(entry, "cn", default="<missing-cn>")
            dn = entry.dn or "<missing-dn>"
            print(f"[progress {idx}/{total}] validating cn={cn} dn={dn}", file=sys.stderr, flush=True)
            results.append(validate_entry(entry, ldap_validator, args.strict_options, verbose=item_verbose))

        patch_generated = False
        if args.output_patch is not None:
            patch_path = resolve_patch_path(input_ldif, args.output_patch)
            fixed_entries, user_fixes, option_fixes, command_fixes = build_patch_fixed_entries(sudo_entries, ldap_validator)
            merged_entries = merge_fixed_sudo_entries(entries, fixed_entries)
            fixed_ldif_text = render_ldif(merged_entries)
            patch_generated = write_ldif_patch(input_ldif, original_ldif_text, fixed_ldif_text, patch_path)

            if patch_generated:
                print(
                    "\nPatch file created: "
                    f"{patch_path} "
                    f"(sudoUser fixes: {user_fixes}, sudoOption fixes/removals: {option_fixes}, "
                    f"sudoCommand removals: {command_fixes})"
                )
                print("Apply with: patch < " + str(patch_path))
            else:
                print("\nNo patch changes were needed; no patch file written.")
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
