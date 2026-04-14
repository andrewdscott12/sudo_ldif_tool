#!/usr/bin/env python3
"""
sudo_to_ldif.py - Convert sudo policy report data to consolidated LDIF sudoRole objects.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from ldap3 import ALL, BASE, Connection, Server
except Exception:  # pragma: no cover - optional dependency at runtime
    Connection = None
    Server = None
    ALL = None
    BASE = None


# Base DN for generated sudoRole objects.
SUDO_BASE_DN = "ou=SUDOers,dc=example,dc=com"

DEFAULT_HOST_ALL_THRESHOLD = 25
USER_NAME_ATTRS = ("uid", "sAMAccountName", "cn")

KNOWN_LDAP_OPTION_NAMES = {
    "authenticate",
    "requiretty",
    "noexec",
    "setenv",
    "env_reset",
    "always_set_home",
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
    "verifypw",
    "listpw",
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


@dataclass(frozen=True)
class ParsedRule:
    host_spec: str
    runas_users: Tuple[str, ...]
    commands: Tuple[str, ...]
    option_tokens: Tuple[str, ...]


@dataclass
class PolicyAggregate:
    cn_base: str
    sudo_users: Set[str]
    hosts: Set[str]
    commands: Set[str]
    runas_users: Set[str]
    options: Set[str]
    source_files: Set[str]


class LdapGroupResolver:
    def __init__(
        self,
        server_uri: str,
        bind_dn: Optional[str],
        bind_password: Optional[str],
        search_base: str,
        user_attr: str = "uid",
    ) -> None:
        self._enabled = bool(server_uri and search_base and Server and Connection)
        self._conn: Optional[Any] = None
        self._search_base = search_base
        self._user_attr = user_attr
        self._group_cache: Dict[str, Set[str]] = {}
        self._user_dn_cache: Dict[str, Optional[str]] = {}

        if not self._enabled:
            return

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

    @property
    def enabled(self) -> bool:
        return self._enabled and self._conn is not None

    def close(self) -> None:
        if self._conn is not None and self._conn.bound:
            self._conn.unbind()

    def resolve_group_members(self, group_name: str) -> Set[str]:
        if not self.enabled:
            return set()

        if group_name in self._group_cache:
            return set(self._group_cache[group_name])

        escaped = ldap_filter_escape(group_name)
        # Active Directory group lookup by name.
        filter_expr = f"(&(objectClass=group)(|(cn={escaped})(sAMAccountName={escaped})))"

        assert self._conn is not None
        self._conn.search(
            search_base=self._search_base,
            search_filter=filter_expr,
            attributes=["member"],
            size_limit=1,
        )

        if not self._conn.entries:
            self._group_cache[group_name] = set()
            return set()

        entry = self._conn.entries[0]
        members: Set[str] = set()

        # AD stores group members as user DNs in `member`.
        dns: List[str] = []
        if hasattr(entry, "member") and entry.member:
            dns.extend(str(v).strip() for v in entry.member.values if str(v).strip())

        for dn in dns:
            user_value = self._resolve_user_dn(dn)
            if user_value:
                members.add(user_value)

        self._group_cache[group_name] = members
        return set(members)

    def _resolve_user_dn(self, dn: str) -> Optional[str]:
        if dn in self._user_dn_cache:
            return self._user_dn_cache[dn]

        assert self._conn is not None
        self._conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[self._user_attr, *USER_NAME_ATTRS],
            size_limit=1,
        )

        if not self._conn.entries:
            self._user_dn_cache[dn] = None
            return None

        entry = self._conn.entries[0]

        candidates = [self._user_attr, *USER_NAME_ATTRS]
        for attr in candidates:
            if hasattr(entry, attr):
                values = getattr(entry, attr).values
                if values:
                    value = str(values[0]).strip()
                    if value:
                        self._user_dn_cache[dn] = value
                        return value

        self._user_dn_cache[dn] = None
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert sudo policy report CSV into consolidated LDAP sudoRole LDIF. "
            "Supports optional LDAP group membership expansion."
        )
    )
    parser.add_argument("source_csv", help="Path to source CSV report")
    parser.add_argument("output_ldif", help="Path to output LDIF file")
    parser.add_argument(
        "--base-dn",
        default=SUDO_BASE_DN,
        help=f"Base DN for generated sudoRole objects (default: {SUDO_BASE_DN})",
    )
    parser.add_argument(
        "--host-all-threshold",
        type=int,
        default=DEFAULT_HOST_ALL_THRESHOLD,
        help=(
            "When a consolidated policy appears on more than this many hosts, "
            "emit sudoHost: ALL instead of listing hosts (default: 25)"
        ),
    )
    parser.add_argument("--ldap-uri", help="LDAP URI (e.g. ldaps://ldap.example.com)")
    parser.add_argument("--ldap-bind-dn", help="LDAP bind DN")
    parser.add_argument("--ldap-bind-password", help="LDAP bind password")
    parser.add_argument("--ldap-search-base", help="LDAP search base for groups/users")
    parser.add_argument(
        "--ldap-user-attr",
        default="uid",
        help="Preferred LDAP attribute to map group members to sudoUser values (default: uid)",
    )
    return parser.parse_args()


def normalize_csv_row(raw: List[str]) -> Optional[Tuple[str, str, str, str, str]]:
    if not raw:
        return None

    row_text = ",".join(raw).strip()
    if not row_text or row_text.startswith("###"):
        return None

    lower = row_text.lower()
    if lower.startswith("hostname,user|group") or lower.startswith("hostname,policyfile"):
        return None

    if len(raw) >= 5:
        # Supported 5-column layouts:
        # 1) hostname,user|group,subject_name,policyfile,policy_line
        # 2) hostname,policyfile,user|group,subject_name,policy_line
        c1, c2, c3, c4 = raw[0:4]
        if c2.strip().lower() in {"user", "group"}:
            hostname, subject_type, subject_name, policyfile = c1, c2, c3, c4
        elif c3.strip().lower() in {"user", "group"} and _looks_like_policy_path(c2):
            hostname, policyfile, subject_type, subject_name = c1, c2, c3, c4
        else:
            return None
        policy_line = ",".join(raw[4:])
    elif len(raw) == 4:
        # Some wrapped Defaults lines can be shifted into a 4-column shape like:
        # hostname,/etc/sudoers.d/policy/group,Defaults:%grp,!requiretty
        c1, c2, c3, c4 = raw
        if _looks_like_policy_path(c2) and c3.strip().lower().startswith("defaults:"):
            hostname = c1.strip()
            policyfile, suffix_subject_type = _split_policyfile_subject_type(c2)
            subject_type = suffix_subject_type
            subject_name = c3.split(":", 1)[1].strip().lstrip("%") or "unknown"
            policy_line = f"{c3} {c4}".strip()

            if not (hostname and policyfile and subject_type and subject_name and policy_line):
                return None

            return hostname, subject_type, subject_name, policyfile, policy_line

        hostname, subject_type, subject_name, policy_blob = raw
        if ":" in policy_blob:
            policyfile, policy_line = policy_blob.split(":", 1)
        else:
            policyfile, policy_line = "unknown", policy_blob
    else:
        return None

    hostname = hostname.strip()
    subject_type = subject_type.strip().lower()
    subject_name = subject_name.strip()
    policyfile = policyfile.strip()
    policy_line = policy_line.strip()

    if not (hostname and subject_type and subject_name and policy_line):
        return None

    if subject_type not in {"user", "group"}:
        return None

    return hostname, subject_type, subject_name, policyfile, policy_line


def _looks_like_policy_path(value: str) -> bool:
    candidate = value.strip().lower()
    if not candidate:
        return False
    return candidate.startswith("/") or "sudoers" in candidate


def _split_policyfile_subject_type(policyfile_raw: str) -> Tuple[str, str]:
    candidate = policyfile_raw.strip()
    suffix_match = re.match(r"^(?P<path>.+?)/(?P<stype>user|group)$", candidate, flags=re.IGNORECASE)
    if not suffix_match:
        return candidate, "group"
    return suffix_match.group("path").strip(), suffix_match.group("stype").lower()


def parse_sudo_policy_line(policy_line: str) -> ParsedRule:
    cleaned = " ".join(policy_line.strip().split())
    if not cleaned:
        return ParsedRule("ALL", tuple(), tuple(["ALL"]), tuple())

    if cleaned.lower().startswith("defaults"):
        defaults_options = {translate_sudo_option(t) for t in _parse_defaults_options(cleaned)}
        if "!requiretty" in defaults_options:
            defaults_options.discard("requiretty")
        if "!authenticate" in defaults_options:
            defaults_options.discard("authenticate")
        # Defaults lines carry options rather than explicit command grants.
        return ParsedRule("ALL", tuple(), tuple(), tuple(sorted(defaults_options)))

    # Support both forms:
    # 1) <who> <hostspec>=(<runas>) <cmdspec>
    # 2) <who> <hostspec>=<cmdspec> (no explicit runas)
    match = re.match(
        r"^(?P<who>\S+)\s+(?P<host>\S+)\s*=\s*(?:\((?P<runas>[^)]*)\)\s*)?(?P<cmd>.+)$",
        cleaned,
    )
    if match:
        host_spec = match.group("host").strip()
        runas_raw = (match.group("runas") or "").strip()
        cmdspec = match.group("cmd").strip()
    else:
        # Also support compact forms seen in exports, e.g.:
        # ALL(ALL) NOPASSWD: /bin/bash
        # ALL(root) /bin/systemctl
        compact = re.match(
            r"^(?P<host>\S+)\s*\((?P<runas>[^)]*)\)\s*(?P<cmd>.+)$",
            cleaned,
        )
        host_eq = re.match(
            r"^(?P<host>\S+)\s*=\s*(?:\((?P<runas>[^)]*)\)\s*)?(?P<cmd>.+)$",
            cleaned,
        )
        if compact:
            host_spec = compact.group("host").strip()
            runas_raw = (compact.group("runas") or "").strip()
            cmdspec = compact.group("cmd").strip()
        elif host_eq:
            host_spec = host_eq.group("host").strip()
            runas_raw = (host_eq.group("runas") or "").strip()
            cmdspec = host_eq.group("cmd").strip()
        else:
            # Before treating the whole string as a bare command, check whether it
            # is really a standalone option token (e.g. "!requiretty", "NOPASSWD:").
            # This happens when a CSV row contains only an option spec with no
            # host/runas structure – the token should become a sudoOption, not a
            # sudoCommand.
            parts = _split_csvish_values(cleaned)
            opt_parts = [t.rstrip(":") for t in parts if t]
            if opt_parts and all(_looks_like_option_token(t) for t in opt_parts):
                translated = {translate_sudo_option(t) for t in opt_parts if t}
                return ParsedRule("ALL", tuple(), tuple(), tuple(sorted(translated)))
            # Fall back to preserving entire token stream as a single command.
            return ParsedRule("ALL", tuple(), tuple([cleaned]), tuple())

    runas_users = (
        tuple(sorted({_normalize_runas_value(v) for v in _split_csvish_values(runas_raw)}))
        if runas_raw
        else tuple()
    )
    command_parts = _split_csvish_values(cmdspec)

    option_tokens: List[str] = []
    commands: List[str] = []

    for part in command_parts:
        p = part.strip()
        if not p:
            continue

        # Some exports embed host/runas in the command segment itself.
        embedded = re.match(
            r"^(?P<host>\S+)\s*\((?P<runas>[^)]*)\)\s*(?P<rest>.+)$",
            p,
        )
        if embedded:
            embedded_host = embedded.group("host").strip()
            embedded_runas = (embedded.group("runas") or "").strip()
            if embedded_host:
                host_spec = embedded_host
            if embedded_runas:
                for value in _split_csvish_values(embedded_runas):
                    runas_value = _normalize_runas_value(value)
                    if runas_value:
                        runas_users = tuple(sorted(set(runas_users) | {runas_value}))
            p = embedded.group("rest").strip()
            if not p:
                continue

        # Consume leading option fragments until a command token remains.
        while True:
            opt_token, rest = _extract_leading_option_token(p)
            if not opt_token:
                break
            option_tokens.append(opt_token)
            p = rest
            if not p:
                break

        p = re.sub(r"\s+", " ", p).strip()
        if not p:
            continue

        # Extract one or more leading option tokens:
        # NOPASSWD: /bin/cmd
        # NOPASSWD:/bin/cmd
        # NOPASSWD : /bin/cmd
        while True:
            opt_match = re.match(r"^(?P<opt>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<rest>.*)$", p)
            if not opt_match:
                break
            option_tokens.append(opt_match.group("opt"))
            p = opt_match.group("rest").strip()
            if not p:
                break

        # Handle bare LDAP-style option tokens that occupy the entire segment,
        # e.g. !requiretty or secure_path=/usr/sbin:/usr/bin.
        if p and _looks_like_option_token(p):
            option_tokens.append(p)
            continue

        if p:
            commands.append(p)

    translated_options = {translate_sudo_option(token) for token in option_tokens if token.strip()}

    if not commands and not translated_options:
        commands = ["ALL"]

    # Negated options should win if both forms are present.
    if "!authenticate" in translated_options:
        translated_options.discard("authenticate")
    if "noexec" in translated_options:
        translated_options.discard("!noexec")
    if "!setenv" in translated_options:
        translated_options.discard("setenv")
    if "!log_input" in translated_options:
        translated_options.discard("log_input")
    if "!log_output" in translated_options:
        translated_options.discard("log_output")
    if "!follow" in translated_options:
        translated_options.discard("follow")
    if "!intercept" in translated_options:
        translated_options.discard("intercept")
    if "!requiretty" in translated_options:
        translated_options.discard("requiretty")

    return ParsedRule(
        host_spec=host_spec or "ALL",
        runas_users=tuple(runas_users),
        commands=tuple(commands),
        option_tokens=tuple(sorted(translated_options)),
    )


def _extract_leading_option_token(text: str) -> Tuple[Optional[str], str]:
    # Tag form: NOPASSWD: /bin/bash
    colon_tag = re.match(r"^(?P<opt>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<rest>.+)$", text)
    if colon_tag:
        return colon_tag.group("opt"), colon_tag.group("rest").strip()

    # LDAP option form: !requiretty /bin/bash or requiretty /bin/bash
    bare = re.match(r"^(?P<opt>!?[A-Za-z_][A-Za-z0-9_]*(?:=[^\s,]+)?)\s+(?P<rest>.+)$", text)
    if bare:
        token = bare.group("opt")
        if _looks_like_option_token(token):
            return token, bare.group("rest").strip()

    return None, text


def _parse_defaults_options(cleaned_defaults: str) -> List[str]:
    # Examples:
    # Defaults:%group !requiretty,env_reset
    # Defaults !authenticate
    parts = cleaned_defaults.split(None, 1)
    if len(parts) < 2:
        return []

    option_blob = parts[1].strip()
    # Drop selector prefix like %group / :user / @host if present.
    option_blob = re.sub(r"^[^\s]+\s+", "", option_blob)

    tokens = [t.strip() for t in option_blob.split(",") if t.strip()]
    return [token for token in tokens if _looks_like_option_token(token)]


def _looks_like_option_token(token: str) -> bool:
    cleaned = token.strip()
    if not cleaned:
        return False

    negated = cleaned.startswith("!")
    core = cleaned[1:] if negated else cleaned
    core_upper = core.upper()
    core_lower = core.lower()

    if core_upper in TAG_TO_LDAP_OPTION:
        return True
    if core_lower in KNOWN_LDAP_OPTION_NAMES:
        return True
    if core_upper.startswith("NO") and core_upper[2:].lower() in KNOWN_LDAP_OPTION_NAMES:
        return True
    if "=" in core:
        key = core.split("=", 1)[0].lower()
        if key in KNOWN_LDAP_OPTION_NAMES:
            return True
    return False


def _normalize_runas_value(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    # LDAP sudoRunAsUser generally expects concrete names; map ALL to root.
    if cleaned.upper() == "ALL":
        return "root"
    return cleaned


def _split_csvish_values(raw: str) -> List[str]:
    values = [p.strip() for p in raw.split(",")]
    return [v for v in values if v]


@dataclass(frozen=True)
class PolicyRecord:
    hostname: str
    subject_type: str
    subject_name: str
    policyfile: str
    parsed: ParsedRule


@dataclass
class PendingPolicyRecord:
    hostname: str
    subject_type: str
    subject_name: str
    policyfile: str
    policy_line: str


@dataclass
class CsvParseDiagnostics:
    total_rows: int = 0
    skipped_rows: int = 0
    invalid_rows: int = 0
    invalid_samples: List[str] = None

    def __post_init__(self) -> None:
        if self.invalid_samples is None:
            self.invalid_samples = []


def _format_row_sample(raw_row: List[str], max_cell_length: int = 80) -> str:
    if not raw_row:
        return "<empty row>"

    rendered_cells: List[str] = []
    for cell in raw_row:
        snippet = cell.strip().replace("\n", " ")
        if len(snippet) > max_cell_length:
            snippet = snippet[: max_cell_length - 3] + "..."
        rendered_cells.append(snippet)
    return " | ".join(rendered_cells)


def _classify_invalid_row(raw_row: List[str]) -> str:
    if not raw_row:
        return "empty row"

    if len(raw_row) < 4:
        if len(raw_row) == 1 and (";" in raw_row[0] or "\t" in raw_row[0]):
            return "looks like non-comma delimiter (found ';' or tab)"
        return f"too few columns ({len(raw_row)}); expected 4 or 5"

    if len(raw_row) > 5:
        return f"more than 5 columns ({len(raw_row)}); policy text may be misquoted"

    if len(raw_row) >= 3:
        c2 = raw_row[1].strip().lower()
        c3 = raw_row[2].strip().lower()
        if c2 not in {"user", "group"} and c3 not in {"user", "group"}:
            return "missing user/group marker; expected in column 2 or 3"

    subject_type = raw_row[1].strip().lower() if len(raw_row) > 1 else ""
    if subject_type not in {"user", "group"}:
        return "column 2 must be 'user'/'group' (old layout) or column 3 (path-first layout)"

    return "missing required value(s)"


def _build_csv_format_error_message(source_csv: Path, diagnostics: CsvParseDiagnostics) -> str:
    sample_lines: List[str] = []
    for idx, sample in enumerate(diagnostics.invalid_samples, start=1):
        sample_lines.append(f"  {idx}. {sample}")

    expected = [
        "Expected CSV format:",
        "  5-column form (legacy):",
        "    hostname,user|group,subject_name,policyfile,policy_line",
        "  5-column form (path-first):",
        "    hostname,policyfile,user|group,subject_name,policy_line",
        "  4-column form:",
        "    hostname,user|group,subject_name,policyfile:policy_line",
        "  Notes:",
        "    - Delimiter must be a comma ','",
        "    - user|group marker is required (column 2 for legacy, column 3 for path-first)",
        "    - Header rows and lines starting with '###' are ignored",
    ]

    details = [
        f"CSV format check failed for {source_csv}.",
        f"Read {diagnostics.total_rows} rows, skipped {diagnostics.skipped_rows}, and could not parse {diagnostics.invalid_rows} rows.",
    ]

    if sample_lines:
        details.append("Sample problematic input rows:")
        details.extend(sample_lines)

    details.append("")
    details.extend(expected)
    return "\n".join(details)


def build_policy_records(source_csv: Path) -> List[PolicyRecord]:
    records: List[PolicyRecord] = []
    diagnostics = CsvParseDiagnostics()
    pending: Optional[PendingPolicyRecord] = None

    def flush_pending() -> None:
        nonlocal pending
        if not pending:
            return

        parsed_pending = parse_sudo_policy_line(_finalize_policy_line(pending.policy_line))
        records.append(
            PolicyRecord(
                hostname=pending.hostname,
                subject_type=pending.subject_type,
                subject_name=pending.subject_name,
                policyfile=pending.policyfile,
                parsed=parsed_pending,
            )
        )
        pending = None

    with source_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for raw_row in reader:
            diagnostics.total_rows += 1

            if pending and _is_policy_continuation_row(raw_row, pending):
                fragment = _extract_policy_continuation_fragment(raw_row)
                pending.policy_line = _append_policy_continuation(pending.policy_line, fragment)
                if not _line_continues(pending.policy_line):
                    flush_pending()
                continue

            if pending and not _is_policy_continuation_row(raw_row, pending):
                flush_pending()

            normalized = normalize_csv_row(raw_row)
            if not normalized:
                row_text = ",".join(raw_row).strip()
                lower = row_text.lower()
                if (not row_text) or row_text.startswith("###") or lower.startswith("hostname,user|group") or lower.startswith("hostname,policyfile"):
                    diagnostics.skipped_rows += 1
                    continue

                diagnostics.invalid_rows += 1
                if len(diagnostics.invalid_samples) < 5:
                    reason = _classify_invalid_row(raw_row)
                    sample = _format_row_sample(raw_row)
                    diagnostics.invalid_samples.append(f"{sample}  [{reason}]")
                continue

            hostname, subject_type, subject_name, policyfile, policy_line = normalized
            if _line_continues(policy_line):
                pending = PendingPolicyRecord(
                    hostname=hostname,
                    subject_type=subject_type,
                    subject_name=subject_name,
                    policyfile=policyfile,
                    policy_line=policy_line,
                )
                continue

            parsed = parse_sudo_policy_line(_finalize_policy_line(policy_line))
            records.append(
                PolicyRecord(
                    hostname=hostname,
                    subject_type=subject_type,
                    subject_name=subject_name,
                    policyfile=policyfile,
                    parsed=parsed,
                )
            )

    if pending:
        flush_pending()

    if not records and diagnostics.invalid_rows:
        raise ValueError(_build_csv_format_error_message(source_csv, diagnostics))

    return records


def _line_continues(policy_line: str) -> bool:
    return policy_line.strip().endswith("\\")


def _is_policy_continuation_row(raw_row: List[str], pending: PendingPolicyRecord) -> bool:
    if len(raw_row) < 4:
        return False

    if raw_row[1].strip() != pending.policyfile:
        return False

    continuation_candidate = raw_row[3].strip()
    if not continuation_candidate:
        return False

    # Continuation rows for wrapped command lists typically put command fragments
    # in the subject-name slot (e.g. /bin/true, or /sbin/ifconfig,).
    return continuation_candidate.startswith("/") or continuation_candidate.startswith("!/")


def _extract_policy_continuation_fragment(raw_row: List[str]) -> str:
    return ",".join(raw_row[3:]).strip()


def _append_policy_continuation(base_line: str, fragment: str) -> str:
    base = base_line.strip()
    frag = fragment.strip()
    if base.endswith("\\"):
        base = base[:-1].rstrip()
    if not base:
        return frag
    if not frag:
        return base

    # Wrapped command lists are usually comma-separated in the original sudoers file.
    # Use a comma separator when stitching so each command remains distinct.
    if base.endswith((":", ",")) or frag.startswith(","):
        return f"{base} {frag}".strip()
    return f"{base}, {frag}".strip()


def _finalize_policy_line(policy_line: str) -> str:
    return policy_line.replace("\\", " ").strip()


def _policy_file_key(policyfile: str) -> str:
    source = policyfile.split(":", 1)[0].strip()
    if not source:
        return "unknown"
    return source.rstrip("/").rsplit("/", 1)[-1] or source


def _record_signature(record: PolicyRecord) -> Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    return (
        record.subject_type,
        record.subject_name,
        record.parsed.host_spec,
        record.parsed.runas_users,
        record.parsed.option_tokens,
        tuple(sorted(record.parsed.commands)),
    )


def _new_aggregate(cn_base: str) -> PolicyAggregate:
    return PolicyAggregate(
        cn_base=cn_base,
        sudo_users=set(),
        hosts=set(),
        commands=set(),
        runas_users=set(),
        options=set(),
        source_files=set(),
    )


def build_policy_map(
    source_csv: Path,
    resolver: Optional[LdapGroupResolver],
) -> Dict[str, PolicyAggregate]:
    records = build_policy_records(source_csv)
    policies: Dict[str, PolicyAggregate] = {}

    sudoers_records = [r for r in records if _policy_file_key(r.policyfile).lower() == "sudoers"]
    non_sudoers_records = [r for r in records if _policy_file_key(r.policyfile).lower() != "sudoers"]

    sudoers_signature_hosts: Dict[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]], Set[str]] = defaultdict(set)
    for record in sudoers_records:
        sudoers_signature_hosts[_record_signature(record)].add(record.hostname)

    # Consolidate non-/etc/sudoers content by policy file name.
    for record in non_sudoers_records:
        file_key = _policy_file_key(record.policyfile)
        cn_base = f"SUDO_{sanitize_cn_component(file_key)}"
        if cn_base not in policies:
            policies[cn_base] = _new_aggregate(cn_base)

        _merge_record_into_aggregate(policies[cn_base], record, resolver)

    # /etc/sudoers: shared signatures are consolidated together.
    # One-off signatures are grouped into SUDO_<filename>_<hostname>.
    for record in sudoers_records:
        file_key = _policy_file_key(record.policyfile)
        source_token = sanitize_cn_component(file_key)
        sig_hosts = sudoers_signature_hosts[_record_signature(record)]
        if len(sig_hosts) == 1:
            cn_base = f"SUDO_{source_token}_{sanitize_cn_component(record.hostname)}"
        else:
            cn_base = f"SUDO_{source_token}"

        if cn_base not in policies:
            policies[cn_base] = _new_aggregate(cn_base)

        _merge_record_into_aggregate(policies[cn_base], record, resolver)

    return policies


def _merge_record_into_aggregate(
    aggregate: PolicyAggregate,
    record: PolicyRecord,
    resolver: Optional[LdapGroupResolver],
) -> None:
    sudo_users = resolve_sudo_users(record.subject_type, record.subject_name, resolver)
    if not sudo_users:
        sudo_users = {record.subject_name}

    aggregate.sudo_users.update(sudo_users)
    aggregate.hosts.add(record.hostname)
    aggregate.commands.update(record.parsed.commands)
    aggregate.runas_users.update(record.parsed.runas_users)
    aggregate.options.update(record.parsed.option_tokens)
    if record.policyfile:
        aggregate.source_files.add(record.policyfile)


def build_ldif_entries(
    policies: Dict[str, PolicyAggregate],
    base_dn: str,
    host_all_threshold: int,
) -> List[str]:
    entries: List[str] = []
    cn_counts: Dict[str, int] = defaultdict(int)

    for _key, agg in sorted(policies.items(), key=lambda item: item[1].cn_base.lower()):
        commands_sorted = sorted(agg.commands)
        if not commands_sorted:
            continue

        base_cn = agg.cn_base
        cn_counts[base_cn] += 1
        cn = base_cn if cn_counts[base_cn] == 1 else f"{base_cn}_{cn_counts[base_cn]}"

        if len(agg.hosts) > host_all_threshold:
            sudo_hosts = ["ALL"]
        else:
            sudo_hosts = sorted(agg.hosts)

        lines: List[str] = []
        dn = f"cn={ldap_dn_escape(cn)},{base_dn}"
        lines.append(f"dn: {dn}")
        lines.append("objectClass: top")
        lines.append("objectClass: sudoRole")
        lines.append(f"cn: {cn}")

        for user in sorted(agg.sudo_users):
            lines.append(f"sudoUser: {user.lower()}")

        for host in sudo_hosts:
            lines.append(f"sudoHost: {host}")

        for runas_user in sorted(agg.runas_users):
            lines.append(f"sudoRunAsUser: {runas_user}")

        normalized_agg_options = set(agg.options)
        if "NOPASSWD:" in normalized_agg_options:
            normalized_agg_options.discard("PASSWD:")
        if "NOEXEC:" in normalized_agg_options:
            normalized_agg_options.discard("EXEC:")
        if "NOSETENV:" in normalized_agg_options:
            normalized_agg_options.discard("SETENV:")

        for opt in sorted(normalized_agg_options):
            translated = translate_sudo_option(opt)
            lines.append(f"sudoOption: {translated}")

        for cmd in commands_sorted:
            lines.append(f"sudoCommand: {cmd}")

        if agg.source_files:
            source_summary = ",".join(sorted(agg.source_files))
            lines.append(f"description: source_files={source_summary}")

        entries.append("\n".join(lines))

    return entries


def resolve_sudo_users(
    subject_type: str,
    subject_name: str,
    resolver: Optional[LdapGroupResolver],
) -> Set[str]:
    if subject_type == "user":
        return {subject_name}

    if resolver and resolver.enabled:
        members = resolver.resolve_group_members(subject_name)
        return set(members)

    return set()


def translate_sudo_option(token: str) -> str:
    """
    Translate sudo option tokens (e.g., NOPASSWD:, SETENV:) to LDIF sudoOption format.
    """
    raw = token.strip().rstrip(":")
    if not raw:
        return raw

    if raw.startswith("!"):
        return raw.lower()

    upper = raw.upper()
    lower = raw.lower()

    if upper in TAG_TO_LDAP_OPTION:
        return TAG_TO_LDAP_OPTION[upper]

    if upper.startswith("NO"):
        candidate = upper[2:].lower()
        if candidate in KNOWN_LDAP_OPTION_NAMES:
            return f"!{candidate}"

    if "=" in raw:
        key, value = raw.split("=", 1)
        return f"{key.lower()}={value}"

    if lower in KNOWN_LDAP_OPTION_NAMES:
        return lower

    return lower


def sanitize_cn_component(raw: str) -> str:
    trimmed = raw.strip()
    if not trimmed:
        return "ALL"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", trimmed)
    return safe[:64] if len(safe) > 64 else safe


def ldap_dn_escape(value: str) -> str:
    escaped = value
    escaped = escaped.replace("\\", "\\\\")
    escaped = escaped.replace(",", "\\,")
    escaped = escaped.replace("+", "\\+")
    escaped = escaped.replace('"', '\\"')
    escaped = escaped.replace("<", "\\<")
    escaped = escaped.replace(">", "\\>")
    escaped = escaped.replace(";", "\\;")
    escaped = escaped.replace("=", "\\=")
    if escaped.startswith(" ") or escaped.startswith("#"):
        escaped = "\\" + escaped
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "
    return escaped


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

    source_csv = Path(args.source_csv)
    output_ldif = Path(args.output_ldif)

    if not source_csv.exists():
        print(f"ERROR: Source CSV not found: {source_csv}", file=sys.stderr)
        sys.exit(1)

    resolver: Optional[LdapGroupResolver] = None
    if args.ldap_uri and args.ldap_search_base:
        try:
            resolver = LdapGroupResolver(
                server_uri=args.ldap_uri,
                bind_dn=args.ldap_bind_dn,
                bind_password=args.ldap_bind_password,
                search_base=args.ldap_search_base,
                user_attr=args.ldap_user_attr,
            )
        except Exception as exc:
            print(f"ERROR: Failed to initialize LDAP resolver: {exc}", file=sys.stderr)
            sys.exit(2)

    try:
        try:
            policy_map = build_policy_map(source_csv, resolver)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(3)

        entries = build_ldif_entries(
            policy_map,
            base_dn=args.base_dn,
            host_all_threshold=args.host_all_threshold,
        )

        output_ldif.write_text("\n\n".join(entries) + "\n", encoding="utf-8")
    finally:
        if resolver:
            resolver.close()

    print(f"Wrote {len(entries)} sudoRole entries to {output_ldif}")


if __name__ == "__main__":
    main()
