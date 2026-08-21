"""Kernel log (kern.log) content parser (v1) — nftables drop events.

Scope v1 (frozen contract, project session notes, 2026-08-21):
    - Parses /var/log/kern.log lines produced by nftables `log` statements
      dropping packets. Format confirmed empirically on TWO independent
      real hosts with different nftables logging configurations:
        writer (46.62.147.41):        log prefix "nft-dropped: ",
                                       single concatenated MAC= field
        sysadmin.courses (157.180.66.90): log prefix "DROP INPUT: ",
                                       separate MACSRC=/MACDST=/MACPROTO=
      Both hosts use nftables (confirmed explicitly — NOT an nftables vs
      iptables backend difference, unlike the pre-existing, unrelated
      firewall_config.py backend-identity gap noted elsewhere in this
      project). The difference is purely in each host's own nft ruleset
      `log prefix` and which fields that ruleset's `log` statement
      chooses to emit — a configuration fact, not an architectural one.

    - Over ~1 month of real traffic on both hosts, the ONLY kernel
      message type observed was this nftables drop event. No OOM
      killer, no hardware errors, no USB/driver messages, nothing else.
      This is expected for both hosts (quiet, dedicated servers) and is
      NOT treated as proof no other kernel message type can ever occur
      — same UNKNOWN/UNKNOWN_MESSAGE split as fail2ban_parser.py exists
      specifically so a genuinely new kernel message type is preserved,
      not silently dropped.

Event-type determination is deliberately NOT prefix-based:
    event_type=NFT_DROPPED is decided by the STRUCTURAL signature after
    the prefix (presence of IN=, SRC=, DST=, PROTO= together), not by
    matching a specific literal prefix string ("nft-dropped:" vs
    "DROP INPUT:"). This is why both hosts' formats map to the same
    event_type despite different prefixes and different field sets —
    the prefix itself is not part of the contract; only the field
    structure after it is. A permissive "any line containing SRC= and
    DST=" match was explicitly rejected as too loose (false-positive
    risk) — the parser requires ALL of IN=/SRC=/DST=/PROTO= together,
    the actual structural signature both real hosts share.

Two-level parsing, like fail2ban_parser.py: envelope (timestamp +
hostname + "kernel:" + arbitrary prefix text) + structural field
extraction from the message body, dispatched by field-presence rather
than by a fixed regex shape (since the field SET itself varies by host).

UNKNOWN vs UNKNOWN_MESSAGE (same split, same rationale, as
fail2ban_parser.py):
    UNKNOWN: the envelope itself did not parse (bad timestamp, missing
        "kernel:" marker, garbage/non-str input). We don't know this is
        a kern.log line at all. All fields None except event_type and
        raw_line.
    UNKNOWN_MESSAGE: envelope parsed (timestamp/hostname extracted), but
        the message body doesn't carry the IN=/SRC=/DST=/PROTO=
        structural signature — some other, not-yet-recognized kernel
        message type. Envelope fields preserved; message-specific
        fields (src_ip, dst_ip, etc.) are None.

MAC fields (frozen contract decision — kept SEPARATE, not normalized
into one field): writer's single concatenated MAC= value and courses'
separate MACSRC=/MACDST=/MACPROTO= are structurally different data (one
host logs both MACs concatenated with no explicit protocol field; the
other logs them individually plus the Ethernet protocol code) —
normalizing them into one field would require an invented, lossy
merge rule. Both are preserved as independent optional fields:
    mac        : str | None   (writer-style "MAC=<concat>")
    mac_src    : str | None   (courses-style "MACSRC=")
    mac_dst    : str | None   (courses-style "MACDST=")
    mac_proto  : str | None   (courses-style "MACPROTO=")
Only the fields that actually appeared in a given line are populated;
the others are None for that event.

Timestamp policy (deliberately DIFFERENT from fail2ban_parser.py's UTC
assumption): kern.log timestamps carry an EXPLICIT timezone offset in
every observed line (writer: "+00:00", courses: "+03:00" — the host's
own local time). The offset is parsed FROM the string itself, never
hardcoded to UTC — hardcoding UTC here would silently produce a wrong
absolute timestamp for any host not running in UTC (confirmed real
case: courses runs at +03:00). Microsecond precision is present in the
source (six digits after the decimal point) and is preserved.

Length fields (frozen contract decision): UDP lines carry LEN= TWICE —
once for the overall packet length (near the front, alongside TOS/PREC)
and once for the payload length (at the very end, after DPT=). These
are semantically distinct and both are preserved, never conflated:
    length          : int | None  (first LEN= — overall packet length)
    payload_length  : int | None  (second LEN=, UDP only — payload
                                    length; None for TCP lines, which
                                    only carry LEN= once)

This module is independent from fail2ban_parser.py and the nginx
parsers by design — no shared code assumed until a second/third real
case demonstrates the same abstraction is warranted (same discipline
already applied throughout this project).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class KernLogEventType(Enum):
    NFT_DROPPED = "nft_dropped"
    UNKNOWN_MESSAGE = "unknown_message"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class KernLogEvent:
    """Result of parsing a single kern.log line.

    On UNKNOWN, all fields except event_type and raw_line are None/empty.
    On UNKNOWN_MESSAGE, envelope fields (timestamp/hostname) are
    preserved; all message-specific (NFT_DROPPED-only) fields are None.
    """

    event_type: KernLogEventType
    timestamp: datetime | None
    hostname: str | None
    interface_in: str | None
    interface_out: str | None
    mac: str | None
    mac_src: str | None
    mac_dst: str | None
    mac_proto: str | None
    src_ip: str | None
    dst_ip: str | None
    length: int | None
    tos: str | None
    prec: str | None
    ttl: int | None
    packet_id: int | None
    df_flag: bool
    protocol: str | None
    src_port: int | None
    dst_port: int | None
    window: int | None
    res: str | None
    tcp_flags: list[str] = field(default_factory=list)
    urgp: int | None = None
    payload_length: int | None = None
    raw_line: str = ""


# Envelope: "yyyy-mm-ddThh:mm:ss.ffffff+hh:mm <hostname> kernel: <message>"
# Timestamp offset is captured and parsed explicitly per-line, never
# assumed — see module docstring (writer=+00:00, courses=+03:00, both
# real observed cases).
_ENVELOPE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}:\d{2})"
    r" (?P<hostname>\S+)"
    r" kernel: (?P<message>.*)$"
)

# Structural signature required for NFT_DROPPED: IN=, SRC=, DST=, PROTO=
# must ALL be present together (field order/prefix text is irrelevant —
# see module docstring on why a looser SRC=/DST=-only match was
# explicitly rejected).
_REQUIRED_FIELDS = ("IN=", "SRC=", "DST=", "PROTO=")

_FIELD_PATTERNS = {
    "interface_in": re.compile(r"IN=(\S*)"),
    "interface_out": re.compile(r"OUT=(\S*)"),
    "mac": re.compile(r"(?<!MAC\w)(?<!\w)MAC=(\S+)"),
    "mac_src": re.compile(r"MACSRC=(\S+)"),
    "mac_dst": re.compile(r"MACDST=(\S+)"),
    "mac_proto": re.compile(r"MACPROTO=(\S+)"),
    "src_ip": re.compile(r"(?<!MAC)(?<!\w)SRC=(\S+)"),
    "dst_ip": re.compile(r"(?<!MAC)(?<!\w)DST=(\S+)"),
    "tos": re.compile(r"TOS=(\S+)"),
    "prec": re.compile(r"PREC=(\S+)"),
    "ttl": re.compile(r"TTL=(\d+)"),
    "packet_id": re.compile(r"ID=(\d+)"),
    "protocol": re.compile(r"(?<!MAC)(?<!\w)PROTO=(\S+)"),
    "src_port": re.compile(r"SPT=(\d+)"),
    "dst_port": re.compile(r"DPT=(\d+)"),
    "window": re.compile(r"WINDOW=(\d+)"),
    "res": re.compile(r"RES=(\S+)"),
    "urgp": re.compile(r"URGP=(\d+)"),
}

# All LEN= occurrences, in order: first is overall packet length,
# second (UDP only) is payload length. Matched separately from
# _FIELD_PATTERNS since there can be two.
_LEN_RE = re.compile(r"LEN=(\d+)")

# TCP flags are bare uppercase tokens (SYN, ACK, FIN, RST, PSH, URG, ECE,
# CWR) with no "=" — anything else structural in the line already has an
# "=" sign, so this is unambiguous.
_TCP_FLAG_RE = re.compile(r"\b(SYN|ACK|FIN|RST|PSH|URG|ECE|CWR)\b")


def _has_structural_signature(message: str) -> bool:
    return all(marker in message for marker in _REQUIRED_FIELDS)


def _str_field(pattern: re.Pattern, message: str) -> str | None:
    match = pattern.search(message)
    if match is None:
        return None
    value = match.group(1)
    return value if value else None


def _int_field(pattern: re.Pattern, message: str) -> int | None:
    match = pattern.search(message)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _unknown(line: str) -> KernLogEvent:
    return KernLogEvent(
        event_type=KernLogEventType.UNKNOWN,
        timestamp=None,
        hostname=None,
        interface_in=None,
        interface_out=None,
        mac=None,
        mac_src=None,
        mac_dst=None,
        mac_proto=None,
        src_ip=None,
        dst_ip=None,
        length=None,
        tos=None,
        prec=None,
        ttl=None,
        packet_id=None,
        df_flag=False,
        protocol=None,
        src_port=None,
        dst_port=None,
        window=None,
        res=None,
        tcp_flags=[],
        urgp=None,
        payload_length=None,
        raw_line=line,
    )


def parse_kern_log_line(line: str) -> KernLogEvent:
    """Parse a single kern.log line.

    Never raises. Returns KernLogEvent(event_type=UNKNOWN, ...) if the
    envelope itself cannot be parsed, or
    KernLogEvent(event_type=UNKNOWN_MESSAGE, ...) if the envelope parses
    but the message body does not carry the IN=/SRC=/DST=/PROTO=
    structural signature of a recognized nftables drop event.
    """
    if not isinstance(line, str):
        return _unknown(line if isinstance(line, str) else "")

    match = _ENVELOPE_RE.match(line)
    if match is None:
        return _unknown(line)

    try:
        timestamp = datetime.fromisoformat(match.group("ts"))
    except ValueError:
        return _unknown(line)

    hostname = match.group("hostname")
    message = match.group("message")

    if not _has_structural_signature(message):
        return KernLogEvent(
            event_type=KernLogEventType.UNKNOWN_MESSAGE,
            timestamp=timestamp,
            hostname=hostname,
            interface_in=None,
            interface_out=None,
            mac=None,
            mac_src=None,
            mac_dst=None,
            mac_proto=None,
            src_ip=None,
            dst_ip=None,
            length=None,
            tos=None,
            prec=None,
            ttl=None,
            packet_id=None,
            df_flag=False,
            protocol=None,
            src_port=None,
            dst_port=None,
            window=None,
            res=None,
            tcp_flags=[],
            urgp=None,
            payload_length=None,
            raw_line=line,
        )

    len_values = _LEN_RE.findall(message)
    length = int(len_values[0]) if len_values else None
    payload_length = int(len_values[1]) if len(len_values) > 1 else None

    return KernLogEvent(
        event_type=KernLogEventType.NFT_DROPPED,
        timestamp=timestamp,
        hostname=hostname,
        interface_in=_str_field(_FIELD_PATTERNS["interface_in"], message),
        interface_out=_str_field(_FIELD_PATTERNS["interface_out"], message),
        mac=_str_field(_FIELD_PATTERNS["mac"], message),
        mac_src=_str_field(_FIELD_PATTERNS["mac_src"], message),
        mac_dst=_str_field(_FIELD_PATTERNS["mac_dst"], message),
        mac_proto=_str_field(_FIELD_PATTERNS["mac_proto"], message),
        src_ip=_str_field(_FIELD_PATTERNS["src_ip"], message),
        dst_ip=_str_field(_FIELD_PATTERNS["dst_ip"], message),
        length=length,
        tos=_str_field(_FIELD_PATTERNS["tos"], message),
        prec=_str_field(_FIELD_PATTERNS["prec"], message),
        ttl=_int_field(_FIELD_PATTERNS["ttl"], message),
        packet_id=_int_field(_FIELD_PATTERNS["packet_id"], message),
        df_flag=" DF " in f" {message} ",
        protocol=_str_field(_FIELD_PATTERNS["protocol"], message),
        src_port=_int_field(_FIELD_PATTERNS["src_port"], message),
        dst_port=_int_field(_FIELD_PATTERNS["dst_port"], message),
        window=_int_field(_FIELD_PATTERNS["window"], message),
        res=_str_field(_FIELD_PATTERNS["res"], message),
        tcp_flags=_TCP_FLAG_RE.findall(message),
        urgp=_int_field(_FIELD_PATTERNS["urgp"], message),
        payload_length=payload_length,
        raw_line=line,
    )
