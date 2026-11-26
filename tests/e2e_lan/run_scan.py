"""Runs lan_audit in the scanner container of the network stand and writes
the result as JSON to the file named on the command line (stdout carries
NetAudit's log, netaudit_pkg/utils.py). The container drops to an
unprivileged user before this runs, as NetAudit's service does
(docs/research/network_audit.md §10). CI only."""

import json
import os
import sys

sys.path.insert(0, '/src')

from netaudit_pkg.checks import lan_audit

level2 = sys.argv[1] == '2'
result = lan_audit.check_lan_audit(client='CI stand', authorization=lan_audit.AUTH_CONFIRM,
                                   level2=lan_audit.LEVEL2_CONFIRM if level2 else 'no', interface='eth0')
result['_euid'] = os.geteuid()
with open(sys.argv[2], 'w', encoding='utf-8') as f:
    json.dump(result, f)
