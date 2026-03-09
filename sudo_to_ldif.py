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

# Active Directory configuration: user attributes to try for username extraction (in order of preference)
USER_NAME_ATTRS = ("sAMAccountName", "cn", "uid")


@dataclass(frozen=True)
class ParsedRule:
    host_spec: str
    runas_users: Tuple[str, ...]
    commands: Tuple[str, ...]
    option_tokens: Tuple[str, ...]


@dataclass
class PolicyAggregate:
    subject_type: str
    subject_name: str
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
        # Search for Active Directory groups by cn or sAMAccountName
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

        # Active Directory uses DN-based membership in the 'member' attribute
        if hasattr(entry, "member") and entry.member:
            member_dns = [str(v).strip() for v in entry.member.values if str(v).strip()]
            
            for dn in member_dns:
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

    # Expected format (typical): "<who> <hostspec>=(<runas>) <cmdspec>"
    match = re.match(r"^(?P<who>\S+)\s+(?P<host>\S+)\s*=\s*\((?P<runas>[^)]*)\)\s*(?P<cmd>.+)$", cleaned)
    if not match:
        # Fall back to preserving entire token stream as a single command.
        return ParsedRule("ALL", tuple(), tuple([cleaned]), tuple())

    host_spec = match.group("host").strip()
    runas_raw = match.group("runas").strip()
    cmdspec = match.group("cmd").strip()

    runas_users = tuple(sorted(_split_csvish_values(runas_raw))) if runas_raw else tuple()
    command_parts = _split_csvish_values(cmdspec)

    option_tokens: List[str] = []
    commands: List[str] = []

    for part in command_parts:
        p = part.strip()
        if not p:
            continue

        # Tokens like NOPASSWD:, PASSWD:, SETENV: are exported as sudoOption.
        opt_match = re.match(r"^((?:[A-Z_]+:)\s+)(.+)$", p)
        if opt_match:
            option_tokens.append(opt_match.group(1).strip())
            p = opt_match.group(2).strip()

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


def build_policy_map(source_csv: Path) -> Dict[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...]], PolicyAggregate]:
    policies: Dict[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...]], PolicyAggregate] = {}

    with source_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for raw_row in reader:
            normalized = normalize_csv_row(raw_row)
            if not normalized:
                continue

            hostname, subject_type, subject_name, policyfile, policy_line = normalized
            parsed = parse_sudo_policy_line(policy_line)

            key = (
                subject_type,
                subject_name,
                parsed.host_spec,
                parsed.runas_users,
                parsed.option_tokens,
            )

            if key not in policies:
                policies[key] = PolicyAggregate(
                    subject_type=subject_type,
                    subject_name=subject_name,
                    hosts=set(),
                    commands=set(),
                    runas_users=set(parsed.runas_users),
                    options=set(parsed.option_tokens),
                    source_files=set(),
                )

            agg = policies[key]
            agg.hosts.add(hostname)
            agg.commands.update(parsed.commands)
            if policyfile:
                agg.source_files.add(policyfile)

    return policies


def build_ldif_entries(
    policies: Dict[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...]], PolicyAggregate],
    base_dn: str,
    host_all_threshold: int,
    resolver: Optional[LdapGroupResolver],
) -> List[str]:
    entries: List[str] = []
    cn_counts: Dict[str, int] = defaultdict(int)

    for _key, agg in sorted(
        policies.items(), key=lambda item: (item[1].subject_type, item[1].subject_name, sorted(item[1].commands))
    ):
        commands_sorted = sorted(agg.commands)
        if not commands_sorted:
            continue

        base_cn = f"SUDO_{sanitize_cn_component(commands_sorted[0])}"
        cn_counts[base_cn] += 1
        cn = base_cn if cn_counts[base_cn] == 1 else f"{base_cn}_{cn_counts[base_cn]}"

        sudo_users = resolve_sudo_users(agg.subject_type, agg.subject_name, resolver)
        if not sudo_users:
            # Keep the original subject if expansion produced no user values.
            sudo_users = {agg.subject_name}

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

        for user in sorted(sudo_users):
            lines.append(f"sudoUser: {user}")

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
        policy_map = build_policy_map(source_csv)
        entries = build_ldif_entries(
            policy_map,
            base_dn=args.base_dn,
            host_all_threshold=args.host_all_threshold,
            resolver=resolver,
        )

        output_ldif.write_text("\n\n".join(entries) + "\n", encoding="utf-8")
    finally:
        if resolver:
            resolver.close()

    print(f"Wrote {len(entries)} sudoRole entries to {output_ldif}")


if __name__ == "__main__":
    main()
