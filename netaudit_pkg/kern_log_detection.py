"""Kernel Log Detection (v1) — nftables drop pattern detection.

Scope v1 (frozen contract, project session notes, 2026-08-21):

Pipeline position: Discovery -> Collection -> Kern Log Parser -> Detection
(this module) -> Findings. Detection does NOT search for files, does NOT
re-parse raw lines, does NOT talk to SSH. It receives already-structured
KernLogEvent objects plus a CoverageStatus (derived by the caller from
collection/discovery evidence), looks for behavioral patterns among
NFT_DROPPED events, and emits KernLogSignal objects. Findings (a separate,
not-yet-built module) turns a Signal into a severity-carrying finding —
Detection itself never decides severity.

This module is NOT a mechanical copy of fail2ban_detection.py. kern.log
has a fundamentally different character: fail2ban.log already contains
another system's own verdict (a Ban line means fail2ban itself decided
an IP crossed a threshold and acted) — Detection there just records that
decision. kern.log's NFT_DROPPED events are raw, undigested packet-drop
records with no verdict attached; Detection here must find the pattern
itself, the same kind of work nginx_access_detection.py does over raw
HTTP request/response data. A single NFT_DROPPED line is NEVER, by
itself, a signal — one dropped packet on a closed port is completely
normal firewall operation.

KernLogSignalType v1 (TWO values — a third candidate was reality-checked
and deliberately deferred, see below):
    HIGH_DROP_RATE  per-src_ip, slice-wide, absolute drop count
    PORT_SCAN       per-src_ip, slice-wide, distinct dst_port cardinality
                     (dst_port=None events excluded from cardinality —
                     GRE/SCTP-style protocols carry no port at all, not
                     a scan indicator either way)

DROP_BURST explicitly NOT in v1 (reality-checked and deferred, not
invented-then-rejected): a fixed, non-overlapping windowed signal
(same windowing mechanism as nginx's REQUEST_BURST — grouping by
src_ip, window from epoch=min(timestamp)) was considered as a third
candidate. A real 2000-line/~6-hour sample from writer (46.62.147.41)
was analyzed with a 10-second window before any threshold was chosen:
maximum was 2 drops from one src_ip in any single window, out of 1997
active windows (1994 windows with exactly 1 drop, only 3 with exactly
2, zero with 3+). This data provides no empirical basis for ANY
burst threshold above the noise floor — inventing a number (e.g. "3")
would flag ordinary two-packet activity as a security signal with no
real precedent behind it. Deferred, not implemented with a placeholder
threshold and not silently dropped from the design — if a future real
case (a different host, a different time window, an actual DDoS/SYN-
flood incident) shows a genuine burst pattern, this signal can be
added then, backed by real data, the same discipline already applied
to UPSTREAM_FAILURE (nginx error detection) and JAIL_START_WARNING
(fail2ban detection) — features named in review but built only once a
real case justifies them.

HIGH_DROP_RATE aggregation (frozen): slice-wide (not windowed), grouped
by src_ip, absolute count. threshold=10 chosen from real distribution
on writer: median=1 (i.e. most source IPs are seen exactly once —
routine internet background scanning noise), but a small number of
IPs show sustained high counts (max observed: 307). 10 was not picked
arbitrarily — it separates single/low-count noise from IPs clearly
more active than background, while remaining internally consistent
with this project's other slice-wide absolute-count thresholds (nginx
HIGH_4XX_RATE=10, fail2ban HIGH_ERROR_RATE=10).

PORT_SCAN aggregation (frozen): slice-wide, grouped by src_ip, distinct
dst_port cardinality — events with dst_port=None do not count toward
cardinality (they simply don't participate; they may still contribute
to that src_ip's HIGH_DROP_RATE count independently). threshold=10 is
directly supported by the real distribution's shape, not just
consistency with HIGH_DROP_RATE: >=3 distinct ports matched 117 IPs
(too noisy to be useful), >=5 matched 78, but >=10 dropped sharply to
24 — a clear inflection point in the real data — and >=15 dropped
further to 12. 10 sits right at that inflection.

Unlike nginx's PATH_SCAN, PORT_SCAN has NO secondary ratio component
(no analogue to PATH_SCAN's 404-ratio) — every NFT_DROPPED event is,
by construction, already a dropped packet; there is no "successful vs
unsuccessful" distinction among them the way there is for HTTP status
codes, so a single cardinality threshold is the complete rule.

KernLogSignal.event_count semantics (frozen, differs per signal type —
same asymmetry nginx's PATH_SCAN vs rate-signals already established):
    HIGH_DROP_RATE: event_count = number of matching events (raw count)
    PORT_SCAN:      event_count = number of DISTINCT dst_ports, NOT the
                     raw event count for that src_ip (mirrors nginx
                     PATH_SCAN's event_count=len(distinct_paths))
raw_evidence for PORT_SCAN holds one representative KernLogEvent per
distinct port (not every event on that port) — same evidence-shape
discipline as nginx's path_scan (avoids unbounded memory growth from
repeated hits on the same port).

Coverage semantics — structurally identical to nginx/fail2ban Detection
(COMPLETE/PARTIAL/EMPTY/FAILED/UNKNOWN, EMPTY = strictly "0 parsed
NFT_DROPPED-relevant events"), but an independent enum in this module,
not shared code (same "wait for a second/third real case before
generalizing" principle already applied throughout this project).
detection_succeeded: COMPLETE/PARTIAL/EMPTY -> True, FAILED/UNKNOWN ->
False. A slice with many NFT_DROPPED events, none crossing either
threshold, is coverage=COMPLETE, detection_succeeded=True, signals=[]
— a legitimate, fully-analyzed "nothing notable" result, not an error.

This module is independent from nginx_access_detection.py and
fail2ban_detection.py by design — no shared code assumed until a
second/third real case demonstrates the same abstraction is warranted.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from netaudit_pkg.kern_log_parser import KernLogEvent, KernLogEventType


class CoverageStatus(Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    UNKNOWN = "unknown"


class KernLogSignalType(Enum):
    HIGH_DROP_RATE = "high_drop_rate"
    PORT_SCAN = "port_scan"


# Numeric thresholds v1 — see module docstring for the real-data
# provenance behind each (NOT invented, NOT nginx values copied blindly).
HIGH_DROP_RATE_THRESHOLD = 10
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 10


@dataclass(frozen=True)
class KernLogSignal:
    """One detected behavioral pattern. Signal is a fact ("this src_ip
    exceeded this threshold"), not an interpretation — severity belongs
    to Findings.

    event_count semantics differ by signal_type — see module docstring.
    raw_evidence contains ONLY the events relevant to THIS signal, not
    the whole detection run.
    """

    signal_type: KernLogSignalType
    src_ip: str | None
    event_count: int
    raw_evidence: list[KernLogEvent]


@dataclass(frozen=True)
class KernLogDetectionResult:
    """Top-level Detection output for one collected kern.log slice."""

    coverage: CoverageStatus
    detection_succeeded: bool
    signals: list[KernLogSignal]


def _high_drop_rate_signals(dropped: list[KernLogEvent]) -> list[KernLogSignal]:
    """HIGH_DROP_RATE: per-src_ip absolute count of NFT_DROPPED events,
    slice-wide, no window."""
    by_src: dict[str, list[KernLogEvent]] = defaultdict(list)
    for e in dropped:
        if e.src_ip is None:
            continue
        by_src[e.src_ip].append(e)

    signals = []
    for src_ip, matching in by_src.items():
        if len(matching) >= HIGH_DROP_RATE_THRESHOLD:
            signals.append(
                KernLogSignal(
                    signal_type=KernLogSignalType.HIGH_DROP_RATE,
                    src_ip=src_ip,
                    event_count=len(matching),
                    raw_evidence=matching,
                )
            )
    return signals


def _port_scan_signals(dropped: list[KernLogEvent]) -> list[KernLogSignal]:
    """PORT_SCAN: per-src_ip distinct dst_port cardinality, slice-wide.
    Events with dst_port=None do not participate in cardinality at all."""
    by_src_ports: dict[str, dict[int, KernLogEvent]] = defaultdict(dict)
    for e in dropped:
        if e.src_ip is None or e.dst_port is None:
            continue
        # keep first-seen event per distinct port as the representative
        # evidence entry — mirrors nginx path_scan's evidence shape.
        by_src_ports[e.src_ip].setdefault(e.dst_port, e)

    signals = []
    for src_ip, ports in by_src_ports.items():
        if len(ports) >= PORT_SCAN_DISTINCT_PORTS_THRESHOLD:
            signals.append(
                KernLogSignal(
                    signal_type=KernLogSignalType.PORT_SCAN,
                    src_ip=src_ip,
                    event_count=len(ports),
                    raw_evidence=list(ports.values()),
                )
            )
    return signals


def detect_kern_log_signals(
    events: list[KernLogEvent],
    coverage: CoverageStatus,
) -> KernLogDetectionResult:
    """Runs Kern Log Detection v1 (HIGH_DROP_RATE + PORT_SCAN) over
    `events`, given the already-known `coverage` status from Collection
    evidence (this function does not re-derive coverage itself — that's
    the caller's responsibility, based on CollectionResult/discovery
    evidence).

    See this module's docstring for the full coverage/detection_succeeded
    interaction table and both signal contracts.
    """
    detection_succeeded = coverage in (
        CoverageStatus.COMPLETE,
        CoverageStatus.PARTIAL,
        CoverageStatus.EMPTY,
    )

    if not detection_succeeded:
        return KernLogDetectionResult(
            coverage=coverage,
            detection_succeeded=False,
            signals=[],
        )

    dropped = [e for e in events if e.event_type == KernLogEventType.NFT_DROPPED]

    signals: list[KernLogSignal] = []
    signals.extend(_high_drop_rate_signals(dropped))
    signals.extend(_port_scan_signals(dropped))

    return KernLogDetectionResult(
        coverage=coverage,
        detection_succeeded=True,
        signals=signals,
    )
