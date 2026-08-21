"""RED tests for kern_log_parser.py — Kernel Log Parser Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — envelope structural
  A1. valid envelope, writer-style "nft-dropped:"           -> PARSED (NFT_DROPPED)
  A2. valid envelope, courses-style "DROP INPUT:"             -> PARSED (NFT_DROPPED)
  A3. malformed timestamp                                       -> UNKNOWN
  A4. missing "kernel:" marker                                    -> UNKNOWN
  A5. garbage/hostile input                                        -> UNKNOWN (x2, parametrized)
  A6. non-str input                                                  -> UNKNOWN, never raises (x2, parametrized)

Group B — structural signature dispatch (envelope valid)
  B1. envelope valid, message lacks IN=/SRC=/DST=/PROTO= together -> UNKNOWN_MESSAGE, envelope preserved
  B2. only SRC=/DST= without IN=/PROTO=                              -> UNKNOWN_MESSAGE (insufficient signature)
  B3. full IN=/SRC=/DST=/PROTO= signature                             -> NFT_DROPPED

Group C — writer-style fields (single MAC=, TCP)
  C1. full field extraction from a real writer TCP line
  C2. mac populated, mac_src/mac_dst/mac_proto all None

Group D — courses-style fields (separate MACSRC/MACDST/MACPROTO, UDP)
  D1. MACSRC/MACDST/MACPROTO extracted separately, mac=None
  D2. PROTO=UDP with LEN twice -> length=first, payload_length=second

Group E — edge cases actually observed in real data
  E1. PROTO=47 (GRE) with no SPT/DPT
  E2. PROTO=132-style non-TCP/UDP protocol with no SPT/DPT (sanity, GRE covers the real case)
  E3. DF flag present
  E4. DF flag absent
  E5. IN=enp7s0 (courses, non-default interface — proves interface_in isn't hardcoded)
  E6. TCP flags (SYN) captured as a list

Group F — timestamp / offset handling
  F1. writer +00:00 offset preserved as-is
  F2. courses +03:00 offset preserved as-is, NOT force-converted to UTC
  F3. microseconds preserved

This gives 20+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from netaudit_pkg.kern_log_parser import (
    KernLogEventType,
    parse_kern_log_line,
)

# ---------------------------------------------------------------------------
# Real fixtures, taken verbatim from writer (46.62.147.41) and
# sysadmin.courses (157.180.66.90) live kern.log output.
# ---------------------------------------------------------------------------

WRITER_TCP_LINE = (
    "2026-08-21T18:10:17.197093+00:00 writer kernel: nft-dropped: "
    "IN=eth0 OUT= MAC=92:00:06:c2:f4:ce:d2:74:7f:6e:37:e3:08:00 "
    "SRC=5.61.209.224 DST=46.62.147.41 LEN=40 TOS=0x00 PREC=0x00 TTL=242 "
    "ID=54321 PROTO=TCP SPT=62431 DPT=20504 WINDOW=65535 RES=0x00 SYN URGP=0 "
)

WRITER_UDP_LINE = (
    "2026-08-21T18:14:37.380462+00:00 writer kernel: nft-dropped: "
    "IN=eth0 OUT= MAC=92:00:06:c2:f4:ce:d2:74:7f:6e:37:e3:08:00 "
    "SRC=66.132.172.242 DST=46.62.147.41 LEN=58 TOS=0x00 PREC=0x00 TTL=35 "
    "ID=32292 PROTO=UDP SPT=26408 DPT=4409 LEN=38 "
)

WRITER_GRE_LINE = (
    "2026-07-25T23:41:18.402279+00:00 writer kernel: nft-dropped: "
    "IN=eth0 OUT= MAC=92:00:06:c2:f4:ce:d2:74:7f:6e:37:e3:08:00 "
    "SRC=31.56.209.244 DST=46.62.147.41 LEN=52 TOS=0x00 PREC=0x00 TTL=53 "
    "ID=36324 PROTO=132 "
)

COURSES_UDP_LINE = (
    "2026-08-21T12:10:10.483626+03:00 courses kernel: DROP INPUT: "
    "IN=eth0 OUT= MACSRC=d2:74:7f:6e:37:e3 MACDST=96:00:04:3d:da:0b "
    "MACPROTO=0800 SRC=146.88.241.120 DST=157.180.66.90 LEN=53 TOS=0x00 "
    "PREC=0x00 TTL=54 ID=37738 PROTO=UDP SPT=51869 DPT=27021 LEN=33 "
)

COURSES_GRE_LINE = (
    "2026-08-21T13:38:12.503161+03:00 courses kernel: DROP INPUT: "
    "IN=eth0 OUT= MACSRC=d2:74:7f:6e:37:e3 MACDST=96:00:04:3d:da:0b "
    "MACPROTO=0800 SRC=181.212.109.12 DST=157.180.66.90 LEN=578 TOS=0x00 "
    "PREC=0x00 TTL=49 ID=51958 DF PROTO=47 "
)

COURSES_DF_LINE = (
    "2026-08-21T13:16:17.194612+03:00 courses kernel: DROP INPUT: "
    "IN=eth0 OUT= MACSRC=d2:74:7f:6e:37:e3 MACDST=96:00:04:3d:da:0b "
    "MACPROTO=0800 SRC=165.73.46.84 DST=157.180.66.90 LEN=61 TOS=0x00 "
    "PREC=0x00 TTL=47 ID=52830 DF PROTO=UDP SPT=49971 DPT=23616 LEN=41 "
)

COURSES_ALT_IFACE_LINE = (
    "2026-08-21T18:52:55.905687+03:00 courses kernel: DROP INPUT: "
    "IN=enp7s0 OUT= MACSRC=d2:74:7f:6e:37:e3 MACDST=86:00:00:c5:46:b1 "
    "MACPROTO=0800 SRC=10.10.0.1 DST=10.10.0.2 LEN=332 TOS=0x00 PREC=0x00 "
    "TTL=255 ID=0 PROTO=UDP SPT=67 DPT=68 LEN=312 "
)


# ---------------------------------------------------------------------------
# Group A — envelope structural
# ---------------------------------------------------------------------------


def test_a1_writer_style_valid_envelope_is_parsed():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.event_type == KernLogEventType.NFT_DROPPED
    assert result.hostname == "writer"


def test_a2_courses_style_valid_envelope_is_parsed():
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.event_type == KernLogEventType.NFT_DROPPED
    assert result.hostname == "courses"


def test_a3_malformed_timestamp_is_unknown():
    line = WRITER_TCP_LINE.replace("2026-08-21T18:10:17.197093+00:00", "not-a-timestamp")
    result = parse_kern_log_line(line)
    assert result.event_type == KernLogEventType.UNKNOWN
    assert result.timestamp is None
    assert result.hostname is None
    assert result.src_ip is None


def test_a4_missing_kernel_marker_is_unknown():
    line = WRITER_TCP_LINE.replace("kernel:", "systemd:")
    result = parse_kern_log_line(line)
    assert result.event_type == KernLogEventType.UNKNOWN


@pytest.mark.parametrize("line", ["", "this is not a kern.log line at all"])
def test_a5_garbage_input_is_unknown(line):
    result = parse_kern_log_line(line)
    assert result.event_type == KernLogEventType.UNKNOWN
    assert result.raw_line == line


@pytest.mark.parametrize("value", [None, 12345])
def test_a6_non_str_input_is_unknown_never_raises(value):
    result = parse_kern_log_line(value)
    assert result.event_type == KernLogEventType.UNKNOWN


# ---------------------------------------------------------------------------
# Group B — structural signature dispatch
# ---------------------------------------------------------------------------


def test_b1_envelope_valid_message_without_signature_is_unknown_message():
    line = "2026-08-21T18:10:17.197093+00:00 writer kernel: some other kernel message entirely"
    result = parse_kern_log_line(line)
    assert result.event_type == KernLogEventType.UNKNOWN_MESSAGE
    assert result.timestamp is not None
    assert result.hostname == "writer"
    assert result.src_ip is None
    assert result.dst_ip is None


def test_b2_partial_signature_srconly_is_unknown_message():
    line = "2026-08-21T18:10:17.197093+00:00 writer kernel: something SRC=1.2.3.4 DST=5.6.7.8 nothing else"
    result = parse_kern_log_line(line)
    assert result.event_type == KernLogEventType.UNKNOWN_MESSAGE


def test_b3_full_signature_is_nft_dropped():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.event_type == KernLogEventType.NFT_DROPPED


# ---------------------------------------------------------------------------
# Group C — writer-style fields
# ---------------------------------------------------------------------------


def test_c1_writer_tcp_line_full_field_extraction():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.interface_in == "eth0"
    assert result.src_ip == "5.61.209.224"
    assert result.dst_ip == "46.62.147.41"
    assert result.length == 40
    assert result.ttl == 242
    assert result.packet_id == 54321
    assert result.protocol == "TCP"
    assert result.src_port == 62431
    assert result.dst_port == 20504
    assert result.window == 65535
    assert "SYN" in result.tcp_flags
    assert result.urgp == 0


def test_c2_writer_mac_populated_courses_mac_fields_none():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.mac == "92:00:06:c2:f4:ce:d2:74:7f:6e:37:e3:08:00"
    assert result.mac_src is None
    assert result.mac_dst is None
    assert result.mac_proto is None


# ---------------------------------------------------------------------------
# Group D — courses-style fields
# ---------------------------------------------------------------------------


def test_d1_courses_mac_fields_separate_writer_mac_none():
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.mac is None
    assert result.mac_src == "d2:74:7f:6e:37:e3"
    assert result.mac_dst == "96:00:04:3d:da:0b"
    assert result.mac_proto == "0800"


def test_d1b_courses_src_dst_ip_not_confused_with_macsrc_macdst():
    # Regression: SRC=/DST= regex must not match the SRC=/DST= substring
    # inside MACSRC=/MACDST= — found via manual verification after the
    # initial implementation passed all scenario-table tests but still
    # extracted the MAC address into src_ip/dst_ip on courses-style lines.
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.src_ip == "146.88.241.120"
    assert result.dst_ip == "157.180.66.90"
    assert result.src_ip != result.mac_src
    assert result.dst_ip != result.mac_dst


def test_d1c_courses_protocol_not_confused_with_macproto():
    # Same class of regression as test_d1b, for PROTO=/MACPROTO=.
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.protocol == "UDP"
    assert result.protocol != result.mac_proto


def test_d2_udp_length_and_payload_length_distinct():
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.length == 53
    assert result.payload_length == 33


# ---------------------------------------------------------------------------
# Group E — edge cases actually observed in real data
# ---------------------------------------------------------------------------


def test_e1_gre_protocol_no_ports():
    result = parse_kern_log_line(WRITER_GRE_LINE)
    assert result.event_type == KernLogEventType.NFT_DROPPED
    assert result.protocol == "132"
    assert result.src_port is None
    assert result.dst_port is None


def test_e2_courses_gre_protocol_no_ports():
    result = parse_kern_log_line(COURSES_GRE_LINE)
    assert result.event_type == KernLogEventType.NFT_DROPPED
    assert result.protocol == "47"
    assert result.src_port is None
    assert result.dst_port is None
    assert result.df_flag is True


def test_e3_df_flag_present():
    result = parse_kern_log_line(COURSES_DF_LINE)
    assert result.df_flag is True


def test_e4_df_flag_absent():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.df_flag is False


def test_e5_non_default_interface_courses():
    result = parse_kern_log_line(COURSES_ALT_IFACE_LINE)
    assert result.interface_in == "enp7s0"


def test_e6_tcp_flags_captured_as_list():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert isinstance(result.tcp_flags, list)
    assert result.tcp_flags == ["SYN"]


# ---------------------------------------------------------------------------
# Group F — timestamp / offset handling
# ---------------------------------------------------------------------------


def test_f1_writer_offset_preserved():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.timestamp.utcoffset() == timedelta(0)


def test_f2_courses_offset_preserved_not_forced_to_utc():
    result = parse_kern_log_line(COURSES_UDP_LINE)
    assert result.timestamp.utcoffset() == timedelta(hours=3)


def test_f3_microseconds_preserved():
    result = parse_kern_log_line(WRITER_TCP_LINE)
    assert result.timestamp.microsecond == 197093
