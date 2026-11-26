"""Prints a short summary of the stand's results for the CI log: verdict,
router, devices with ports, finding ids, what was not checked. CI only."""

import json
import sys
from pathlib import Path

for path in sorted(Path(sys.argv[1]).glob('level*.json')):
    r = json.loads(path.read_text())
    print(f'== {path.name}: verdict={r.get("verdict")} error={r.get("error")} euid={r.get("_euid")}')
    print('router:', {k: (r.get('router') or {}).get(k) for k in ('ip', 'vendor', 'os', 'version', 'version_source')})
    for d in r.get('devices', []):
        print(f'  {d["ip"]:15} {d["kind"]:12} {d["answered"]:9} mac={d.get("mac")} '
              f'ports={[p["port"] for p in d["ports"]]} worst={d.get("worst")}')
    print('findings:', sorted(f.get('id', f['title']) for f in r.get('findings', [])))
    for c in r.get('checked', []):
        if c['status'] != 'ok':
            print(f'  {c["status"]}: {c["item"]} - {c["detail"]}')
