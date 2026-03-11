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
    if lower.startswith("hostname,user|group"):
        return None

    if len(raw) >= 5:
        hostname, subject_type, subject_name, policyfile = raw[0:4]
        policy_line = ",".join(raw[4:])
    elif len(raw) == 4:
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


def parse_sudo_policy_line(policy_line: str) -> ParsedRule:
    cleaned = " ".join(policy_line.strip().split())
    if not cleaned:
        return ParsedRule("ALL", tuple(), tuple(["ALL"]), tuple())

    # Support both forms:
    # 1) <who> <hostspec>=(<runas>) <cmdspec>
    # 2) <who> <hostspec>=<cmdspec> (no explicit runas)
    match = re.match(
        r"^(?P<who>\S+)\s+(?P<host>\S+)\s*=\s*(?:\((?P<runas>[^)]*)\)\s*)?(?P<cmd>.+)$",
        cleaned,
    )
    if not match:
        # Fall back to preserving entire token stream as a single command.
        return ParsedRule("ALL", tuple(), tuple([cleaned]), tuple())

    host_spec = match.group("host").strip()
    runas_raw = (match.group("runas") or "").strip()
    cmdspec = match.group("cmd").strip()

    runas_users = tuple(sorted(_split_csvish_values(runas_raw))) if runas_raw else tuple()
    command_parts = _split_csvish_values(cmdspec)

    option_tokens: List[str] = []
    commands: List[str] = []
    known_option_words = ("NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV")

    for part in command_parts:
        p = part.strip()
        if not p:
            continue

        # If known option tags appear anywhere in the segment, capture them.
        for opt_word in known_option_words:
            if re.search(rf"\b{opt_word}\b", p, flags=re.IGNORECASE):
                option_tokens.append(f"{opt_word}:")

        # Remove inline option tags so they don't leak into sudoCommand values.
        p = re.sub(
            r"\b(?:NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV)\b\s*:?,?\s*",
            " ",
            p,
            flags=re.IGNORECASE,
        )
        
        p = re.sub(r"\s+", " ", p).strip()
        if not p:
            continue

        # Extract one or more leading option tokens:
        # NOPASSWD: /bin/cmd
        # NOPASSWD:/bin/cmd
        # NOPASSWD : /bin/cmd
        while True:
            opt_match = re.match(r"^(?P<opt>[A-Z_]+)\s*:\s*(?P<rest>.*)$", p)
            if not opt_match:
                break
            option_tokens.append(f"{opt_match.group('opt').upper()}:")
            p = opt_match.group("rest").strip()
            if not p:
                break

        if p:
            commands.append(p)

    if not commands:
        commands = ["ALL"]

    return ParsedRule(
        host_spec=host_spec or "ALL",
        runas_users=tuple(runas_users),
        commands=tuple(commands),
        option_tokens=tuple(sorted(set(option_tokens))),
    )


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


def build_policy_records(source_csv: Path) -> List[PolicyRecord]:
    records: List[PolicyRecord] = []

    with source_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for raw_row in reader:
            normalized = normalize_csv_row(raw_row)
            if not normalized:
                continue

            hostname, subject_type, subject_name, policyfile, policy_line = normalized
            parsed = parse_sudo_policy_line(policy_line)
            records.append(
                PolicyRecord(
                    hostname=hostname,
                    subject_type=subject_type,
                    subject_name=subject_name,
                    policyfile=policyfile,
                    parsed=parsed,
                )
            )

    return records


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
    # One-off signatures are grouped into SUDO_suders_<hostname>.
    for record in sudoers_records:
        sig_hosts = sudoers_signature_hosts[_record_signature(record)]
        if len(sig_hosts) == 1:
            cn_base = f"SUDO_suders_{sanitize_cn_component(record.hostname)}"
        else:
            cn_base = "SUDO_sudoers"

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

        for opt in sorted(agg.options):
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
    token_upper = token.strip().upper().rstrip(":")
    
    option_map = {
        "NOPASSWD": "!authenticate",
        "PASSWD": "authenticate",
        "NOEXEC": "noexec",
        "EXEC": "!noexec",
        "SETENV": "setenv",
        "NOSETENV": "!setenv",
    }
    
    return option_map.get(token_upper, token)


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
        policy_map = build_policy_map(source_csv, resolver)
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
