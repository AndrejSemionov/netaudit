"""
The access rules editor of the Network audit tab, run for real
(docs/research/network_access_policy.md §8, review PR A pass 2, A1): the
editor's own code from web/static/index.html, a fake DOM and a fetch whose
answers arrive when the test says. The rest of the suite reads the page as
text; this needs a JS engine - node, on the CI runners - and is skipped
without one.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404 - runs node on a script built here, never on input
from pathlib import Path

import pytest

NODE = shutil.which('node')
pytestmark = pytest.mark.skipif(not NODE, reason='no JS engine here (node runs this on the CI runners)')

INDEX = Path(__file__).resolve().parents[1] / 'web' / 'static' / 'index.html'
START = "// the owner's access rules (docs/research/network_access_policy.md §8): kept as"

# a fake page around the editor: elements by id, and the rules table's
# inputs and selects created from what renderLanRules() writes
HARNESS = r"""
const elements = {};
const el = id => elements[id] || (elements[id] = { id, value: '', textContent: '', disabled: false });
const unesc = s => s.replace(/&#39;|&quot;|&gt;|&lt;|&amp;/g,
  m => ({ '&#39;': "'", '&quot;': '"', '&gt;': '>', '&lt;': '<', '&amp;': '&' }[m]));
const rulesBox = {
  _html: '',
  get innerHTML() { return this._html; },
  set innerHTML(html) {
    this._html = html;
    for (const k of Object.keys(elements)) if (/^lanRule(Src|Dst|Svc|Dec|Note)\d+$|^lanRulesSet$/.test(k)) delete elements[k];
    for (const m of html.matchAll(/<input id="(lanRule\w+?\d+)"[^>]*?value="([^"]*)"/g)) el(m[1]).value = unesc(m[2]);
    for (const m of html.matchAll(/<select id="(lanRuleDec\d+)">([\s\S]*?)<\/select>/g)) {
      const chosen = /<option value="(\w+)" selected/.exec(m[2]);
      el(m[1]).value = chosen ? chosen[1] : 'forbid';
    }
    if (html.includes('id="lanRulesSet"')) el('lanRulesSet');
  },
};
const document = { getElementById: id => (id === 'lanRules' ? rulesBox : (elements[id] || null)) };
el('lanClient'); el('lanRulesStatus');

const requests = [];
function fetch(url, opts = {}) {
  let resolve, reject;
  const answer = new Promise((ok, bad) => { resolve = ok; reject = bad; });
  requests.push({ url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null, resolve, reject });
  return answer;
}
const respond = (i, status, data) => requests[i].resolve({ ok: status < 400, status, json: async () => data });
const tick = () => new Promise(r => setTimeout(r, 0));
const t = key => key;
const escDeep = v => JSON.parse(JSON.stringify(v));

const editor = new Function('document', 'fetch', 't', 'escDeep', EDITOR_SOURCE
  + '\nreturn { loadLanRules, saveLanRules, addLanRule, removeLanRule, readLanRules,'
  + ' state: () => ({ client: LAN_RULES_CLIENT, rev: LAN_RULES_REV, rules: LAN_RULES }) };')(document, fetch, t, escDeep);
const RULE_B = { id: 'r1', source: '192.168.50.0/24', destination: '192.168.30.0/24', service: 'any',
                 decision: 'forbid', note: '' };

async function main() {
  SCENARIO
}
main().then(r => console.log(JSON.stringify(r)), e => console.log(JSON.stringify({ thrown: String(e) })));
"""


def _run(scenario: str) -> dict:
    html = INDEX.read_text(encoding='utf-8')
    start = html.index(START)
    source = html[start:html.index('function lanDeviceCard(', start)]
    script = HARNESS.replace('EDITOR_SOURCE', json.dumps(source)).replace('SCENARIO', scenario)
    proc = subprocess.run([NODE, '-e', script], capture_output=True, text=True, timeout=60, check=False)  # nosec B603
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_a_late_save_answer_never_lands_in_another_clients_editor():
    """Review PR A pass 2: Save A is in flight, the auditor turns to client
    B - nothing else is loaded, added or saved until A's answer is in, and
    B's rules are then saved as B's."""
    got = _run("""
    el('lanClient').value = 'A';
    const loadA = editor.loadLanRules(); await tick();
    respond(0, 200, { client: 'A', revision: 1, rules: [] }); await loadA;
    const saveA = editor.saveLanRules(); await tick();
    const out = { save: { method: requests[1].method, body: requests[1].body } };
    out.lockedWhileSaving = el('lanRulesSet').disabled === true;
    el('lanClient').value = 'B';
    // fired, never awaited: a request that should not exist gets no answer
    editor.loadLanRules(); editor.addLanRule(); editor.saveLanRules(); await tick();
    out.requestsWhileSaving = requests.length;
    out.statusWhileSaving = el('lanRulesStatus').textContent;
    respond(1, 200, { client: 'A', revision: 1, rules: [] }); await saveA;
    out.afterSave = editor.state();
    const loadB = editor.loadLanRules(); await tick();
    respond(requests.length - 1, 200, { client: 'B', revision: 1, rules: [RULE_B] }); await loadB;
    out.afterLoadB = editor.state();
    const saveB = editor.saveLanRules(); await tick();
    out.saveB = requests[requests.length - 1].body;
    respond(requests.length - 1, 200, { client: 'B', revision: 1, rules: [RULE_B] }); await saveB;
    out.end = editor.state();
    return out;
    """)
    assert 'thrown' not in got, got
    assert got['save'] == {'method': 'PUT', 'body': {'client': 'A', 'base_revision': 1, 'rules': []}}
    assert got['lockedWhileSaving'] is True
    assert got['requestsWhileSaving'] == 2                     # no load, add or save of B went out
    assert got['statusWhileSaving'] == 'lan.rules.busy'
    assert got['afterSave'] == {'client': 'A', 'rev': 1, 'rules': []}
    assert got['afterLoadB']['client'] == 'B' and len(got['afterLoadB']['rules']) == 1
    assert got['saveB']['client'] == 'B' and got['saveB']['base_revision'] == 1
    assert [r['id'] for r in got['saveB']['rules']] == ['r1']  # B's rule is kept, not replaced by A's answer
    assert got['end']['client'] == 'B' and len(got['end']['rules']) == 1


def test_a_load_in_flight_blocks_editing_and_a_second_load():
    got = _run("""
    el('lanClient').value = 'A';
    const loadA = editor.loadLanRules(); await tick();
    el('lanClient').value = 'B';
    // fired, never awaited: a request that should not exist gets no answer
    editor.loadLanRules(); editor.addLanRule(); editor.saveLanRules(); await tick();
    const out = { requestsWhileLoading: requests.length, status: el('lanRulesStatus').textContent };
    respond(0, 200, { client: 'A', revision: 2, rules: [RULE_B] }); await loadA;
    out.after = editor.state();
    return out;
    """)
    assert got['requestsWhileLoading'] == 1 and got['status'] == 'lan.rules.busy'
    assert got['after']['client'] == 'A' and got['after']['rev'] == 2 and len(got['after']['rules']) == 1


def test_a_failed_save_unlocks_the_editor_and_changes_nothing():
    got = _run("""
    el('lanClient').value = 'A';
    const loadA = editor.loadLanRules(); await tick();
    respond(0, 200, { client: 'A', revision: 3, rules: [RULE_B] }); await loadA;
    const saveA = editor.saveLanRules(); await tick();
    requests[1].reject(new TypeError('network down')); await saveA;
    const out = { status: el('lanRulesStatus').textContent, after: editor.state() };
    editor.addLanRule();
    out.rowsAfterAdd = editor.state().rules.length;
    const conflict = editor.saveLanRules(); await tick();
    respond(requests.length - 1, 409, { detail: 'the rules are at revision 4' }); await conflict;
    out.conflictStatus = el('lanRulesStatus').textContent;
    out.afterConflict = editor.state().rev;
    return out;
    """)
    assert 'thrown' not in got, got
    assert got['status'].startswith('run.error')
    assert got['after']['rev'] == 3 and len(got['after']['rules']) == 1
    assert got['rowsAfterAdd'] == 2                               # unlocked again
    assert 'revision 4' in got['conflictStatus'] and got['afterConflict'] == 3
