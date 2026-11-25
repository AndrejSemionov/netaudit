"""Runs lan_audit in the scanner container of the network stand and prints
the result as JSON (docs/research/network_audit.md §10). The container drops
to an unprivileged user before this runs, as NetAudit's service does. CI only."""

import json
import os
import sys

sys.path.insert(0, '/src')

from netaudit_pkg.checks import lan_audit

level2 = len(sys.argv) > 1 and sys.argv[1] == '2'
result = lan_audit.check_lan_audit(client='CI stand', authorization=lan_audit.AUTH_CONFIRM,
                                   level2=lan_audit.LEVEL2_CONFIRM if level2 else 'no', interface='eth0')
result['_euid'] = os.geteuid()
print(json.dumps(result))
