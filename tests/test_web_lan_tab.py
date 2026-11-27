"""
The "Network audit" tab (docs/research/network_audit.md §8, contract N8,
PR 1 notes §12): the permission confirmation, a start button run through
the existing /api/stream/start, a map drawn as SVG by the tab's own code,
device cards, findings with advice in both languages. Static checks of
web/static: the suite has no JS engine (as test_web_laravel_tab.py).
"""

from __future__ import annotations

import re
from pathlib import Path

from netaudit_pkg.checks import lan_audit
from tests.test_web_frontend_escaping import HTML_WRITERS, _functions, _script
from tests.test_web_wordpress_tab import INDEX, _lang_block

CATALOGUE = (Path(__file__).resolve().parents[1] / 'docs' / 'checks' / 'finding_ids.md').read_text()
CONTROLS = re.findall(r'^\| ((?:NET|RTR)-[A-Z]+-\d{3}) \|', CATALOGUE, re.MULTILINE)
ITEMS = ('discovery', 'range', 'neighbours', 'services', 'broadcast', 'mndp', 'llmnr', 'router', 'router_support',
         'level2')
LIMITS = ('udp', 'os_detection', 'other_subnets', 'known_vulns', 'level2')
KINDS = ('router', 'this_machine', 'windows', 'printer', 'camera', 'nas', 'server', 'phone', 'network', 'unknown')
NEXT = ('router_ssh', 'saved_hosts', 'level2', 'other_vantage')
VERDICTS = ('ok', 'warn', 'danger', 'incomplete', 'not_started')


def test_every_catalogued_control_is_read_by_the_tab():
    assert len(CONTROLS) == 20       # PR 1: 18, PR 2: NET-SEG-001, NET-SEG-002


def test_tab_button_and_page():
    assert re.search(r'<button class="tab-btn" data-tab="lan" onclick="switchTab\(\'lan\'\)" '
                     r'data-i18n="tab.lan">Аудит сети</button>', INDEX)
    nav = INDEX[INDEX.index('<nav class="tabs-nav">'):INDEX.index('</nav>')]
    assert nav.index('data-tab="laravel"') < nav.index('data-tab="lan"') < nav.index('data-tab="trends"')
    page = INDEX[INDEX.index('id="tab-lan"'):INDEX.index('id="tab-trends"')]
    for part in ('id="lanClient"', 'id="lanAuth"', 'id="lanLevel2"', 'id="lanAi"', 'id="lanIface"',
                 'onclick="runLanAudit()"', 'id="lanStatus"', 'id="lanResult"'):
        assert part in page, part
    assert re.search(r'<input[^>]+id="lanAuth"[^>]+type="checkbox"|<input[^>]+type="checkbox"[^>]+id="lanAuth"', page)


def test_labels_in_both_languages():
    keys = ['tab.lan', 'cat.lan', 'lan.title', 'lan.hint', 'lan.client', 'lan.auth', 'lan.auth_hint', 'lan.level2',
            'lan.level2_hint', 'lan.ai', 'lan.iface', 'lan.start', 'lan.need_auth', 'lan.running', 'lan.map',
            'lan.devices', 'lan.you', 'lan.router', 'lan.no_answer', 'lan.limits', 'lan.next', 'lan.col.ip',
            'lan.col.name', 'lan.col.mac', 'lan.col.kind', 'lan.col.ports', 'lan.col.problems', 'lan.device',
            'lan.guessed', 'lan.answered.neighbour', 'lan.random_mac', 'lan.vantage', 'lan.scanned',
            'lan.gateway', 'lan.wifi', 'lan.cable', 'lan.version_from', 'lan.unknown_vendor', 'lan.support']
    keys += [f'lan.verdict.{v}' for v in VERDICTS] + [f'lan.item.{i}' for i in ITEMS]
    keys += [f'lan.limit.{i}' for i in LIMITS] + [f'lan.kind.{k}' for k in KINDS] + [f'lan.next.{n}' for n in NEXT]
    keys += [f'lan.title.{c}' for c in CONTROLS] + [f'lan.fix.{c}' for c in CONTROLS]
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in keys:
            assert f"'{key}':" in block, (lang, key)


def test_russian_advice_is_russian():
    block = _lang_block('ru')
    for control in CONTROLS:
        text = re.search(rf"'lan\.fix\.{control}': '([^']*)'", block).group(1)
        assert re.search('[а-яё]', text, re.IGNORECASE), control


def test_check_list_names_the_lan_category():
    assert "lan: t('cat.lan')" in _functions(_script())['renderCheckList']


def test_audit_runs_through_the_stream_with_the_exact_confirmations():
    body = _functions(_script())['runLanAudit']
    assert "fetch('/api/stream/start'" in body
    assert "id: 'lan_audit'" in body
    assert "new EventSource('/api/stream/' + " in body
    assert 'out.innerHTML = renderLan(result);' in body
    assert HTML_WRITERS.get('runLanAudit') == 'escapes'
    # no start without the box ticked; the values are the check's own strings
    assert "t('lan.need_auth')" in body
    script = _script()
    assert f"'{lan_audit.AUTH_CONFIRM}'" in script
    assert f"'{lan_audit.LEVEL2_CONFIRM}'" in script


def test_result_view_escapes_once_and_is_shared_with_the_audit_tab():
    functions = _functions(_script())
    assert re.search(r'^\s*r = escDeep\(r\);\s*LAN_VIEW = r;\s*return lanHtml\(r\);',
                     functions['renderLan'].split('{', 1)[1], re.MULTILINE)
    view = functions['lanHtml']
    for part in ('r.verdict', 'r.checked', 'r.findings', 'r.devices', 'r.router', 'r.vantage', 'r.limits',
                 'r.next_steps', 'r.score', 'lanMapSvg(r)'):
        assert part in view, part
    assert "if (id === 'lan_audit') { LAN_VIEW = r; return { html: lanHtml(r) }; }" in functions['renderResult']


def test_map_is_svg_built_from_the_escaped_copy():
    functions = _functions(_script())
    svg = functions['lanMapSvg']
    assert '<svg' in svg and 'viewBox' in svg
    assert 'd.worst' in svg and 'r.router' in svg and 'r.vantage' in svg
    assert 'showLanDevice(${i})' in svg            # only a row index goes into the handler
    assert 'innerHTML' not in svg                 # it returns markup; the caller writes it


def test_device_card_reads_the_escaped_copy():
    functions = _functions(_script())
    card = functions['showLanDevice']
    assert 'LAN_VIEW' in card and 'innerHTML' in card
    assert HTML_WRITERS.get('showLanDevice') == 'escapes'
    assert 'escDeep' not in card                  # LAN_VIEW is already escaped once


def test_findings_use_the_translated_title_and_advice_by_control():
    view = _functions(_script())['lanHtml'] + _functions(_script())['lanFindingHtml']
    assert "lanControl(f.id)" in view
    assert "'lan.fix.' + control" in view and "'lan.title.' + control" in view


def test_announced_devices_and_per_device_gaps_are_shown():
    """Review #65 pass 1 (P1, P3): a device seen only by its announcement, and
    what could not be checked on a device, are visible on the map and the card."""
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in ('lan.answered.announced', 'lan.gaps', 'lan.legend.gaps', 'lan.item.scripts'):
            assert f"'{key}':" in block, (lang, key)
    functions = _functions(_script())
    svg, card = functions['lanMapSvg'], functions['lanDeviceCard']
    assert 'd.gaps' in svg and 'stroke-dasharray' in svg
    assert 'd.gaps' in card and "t('lan.gaps')" in card
    assert "'announced'" in svg and "t('lan.answered.announced')" in functions['lanHtml']


def test_segments_labels_and_merged_audits_in_the_tab():
    """PR 2 (docs/research/network_audit.md §13): several segments on the map,
    the auditor's names and sensitive marks, audits of one client merged."""
    keys = ['lan.segments', 'lan.seg.name', 'lan.seg.sensitive', 'lan.seg.save', 'lan.seg.saved', 'lan.seg.own',
            'lan.seg.seen_from', 'lan.seg.gateway', 'lan.merge', 'lan.merged', 'lan.item.subnets', 'lan.item.dcs',
            'lan.limit.traceroute', 'lan.kind.domain_controller']
    keys += [f'lan.seg.suggest.{k}' for k in ('accounting', 'servers', 'printers', 'staff', 'guests')]
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in keys:
            assert f"'{key}':" in block, (lang, key)
    functions = _functions(_script())
    assert 'r.segments' in functions['lanMapSvg']
    assert 'saveLanSegment(${i})' in functions['lanHtml']
    save = functions['saveLanSegment']
    assert "fetch('/api/lan/segments'" in save and "method: 'PUT'" in save and 'innerHTML' not in save
    merged = functions['loadLanMerged']
    assert "fetch('/api/lan/merged?client=' + encodeURIComponent(" in merged
    assert 'renderLan(' in merged and HTML_WRITERS.get('loadLanMerged') == 'escapes'


def test_isolation_arrows_start_at_the_segment_the_service_answered_from():
    """Browser check of PR 2: on a merged map "you are here" is the latest
    audit's place, so an arrow starts at the finding's own "from" subnet."""
    svg = _functions(_script())['lanMapSvg']
    assert 'decodeURIComponent(' in svg and "split(':')" in svg
    assert 'ownKey' not in svg

