"""
"iptables INPUT is effectively open" only when nftables does not filter input
either (docs/research/firewall_iptables_backend.md). With the nf_tables
backend `iptables -S` shows only the iptables-nft tables: a native nftables
chain with `policy drop` (live, iptables 1.8.10) still printed
`-P INPUT ACCEPT`, and NetAudit reported a false HIGH.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import _iptables_verdict, audit_firewall
from netaudit_pkg.firewall_config import CommandResult, FileResult, FirewallEvidence
from tests.conftest import ExitCodeFakeSSHExecutor

OPEN_VIEW = '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT'
LEGACY_WARNING = '# Warning: iptables-legacy tables present, use iptables-legacy to see them'

# `nft list ruleset` from the live namespace run
NATIVE_DROP = '''table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}'''

FIREWALLD_STYLE = '''table inet firewalld {
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
		iifname "lo" accept
		jump filter_INPUT_ZONES
		reject with icmpx admin-prohibited
	}
	chain filter_INPUT_ZONES {
		goto filter_IN_public
	}
	chain filter_IN_public {
		tcp dport 22 accept
	}
}'''

JUMP_TO_REJECT = '''table ip guard {
	chain input {
		type filter hook input priority 0; policy accept;
		jump checks
	}
	chain checks {
		tcp dport 22 accept
		reject
	}
}'''

FILTERING = {
    'final counter drop': '''table ip guard {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state established,related accept
		counter packets 12 bytes 3400 drop
	}
}''',
    'log with a quoted drop prefix, then drop': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 22 accept
		log prefix "drop: " drop
	}
}''',
    'firewalld with a trusted docker zone': '''table inet firewalld {
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
		jump filter_INPUT_ZONES
		reject with icmpx admin-prohibited
	}
	chain filter_INPUT_ZONES {
		iifname "docker0" goto filter_IN_docker
		goto filter_IN_public
	}
	chain filter_IN_docker {
		accept
	}
	chain filter_IN_public {
		tcp dport 22 accept
	}
}''',
}

NOT_FILTERING = {
    'accept only': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 22 accept
	}
}''',
    'conditional drop only': '''table ip guard {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state invalid counter packets 0 bytes 0 drop
	}
}''',
    'IPv6-only drops in inet': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		meta nfproto ipv6 drop
		ip6 saddr ::1 drop
	}
}''',
    'unconditional accept before the drop': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		counter accept
		drop
	}
}''',
    'IPv4-wide accept before the drop policy': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		meta nfproto ipv4 accept
	}
}''',
    'conditional reject in a jumped-to chain': '''table ip guard {
	chain input {
		type filter hook input priority 0; policy accept;
		jump checks
	}
	chain checks {
		ip saddr 192.0.2.0/24 reject
	}
}''',
    'forward and output hooks': '''table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy drop;
	}
}''',
    'drop only in a comment or a name': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 22 accept comment "drop the rest later"
		iifname "drop0" accept
	}
}''',
    'ip6 table': '''table ip6 filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
}''',
    'regular chain nobody jumps to': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
	chain unused {
		drop
	}
}''',
    'jump to a missing chain': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		jump nowhere
	}
}''',
    'jump loop': '''table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		jump a
	}
	chain a {
		jump b
	}
	chain b {
		jump a
	}
}''',
    'nat only (docker)': '''table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		oifname != "docker0" ip saddr 172.17.0.0/16 masquerade
	}
}''',
}


def _cr(completed=True, exit_code=0, stdout='', **kwargs) -> CommandResult:
    return CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, command='', **kwargs)


def _evidence(nft=None, iptables=OPEN_VIEW, iptables_stderr='', version=None) -> FirewallEvidence:
    kwargs = {}
    if version is not None:
        kwargs['iptables_version'] = version
    return FirewallEvidence(
        ufw_present=_cr(exit_code=127),
        ufw_status=None,
        nftables_live=nft if nft is not None else _cr(completed=False, exit_code=None),
        nftables_config=FileResult(completed=False, exit_code=None, content='', path='/etc/nftables.conf'),
        iptables_live=_cr(stdout=iptables, stderr=iptables_stderr),
        **kwargs,
    )


# --- verdict -------------------------------------------------------------------

def test_native_nftables_drop_policy_filters_input():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(stdout=NATIVE_DROP)))
    assert verdict == 'FILTERED_BY_NFTABLES'
    assert ctx['chains'] == ['inet filter input']


def test_firewalld_style_reject_in_the_base_chain_filters_input():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(stdout=FIREWALLD_STYLE)))
    assert verdict == 'FILTERED_BY_NFTABLES'
    assert ctx['chains'] == ['inet firewalld filter_INPUT']


def test_unconditional_reject_reached_by_jump_filters_input():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(stdout=JUMP_TO_REJECT)))
    assert verdict == 'FILTERED_BY_NFTABLES'
    assert ctx['chains'] == ['ip guard input']


def test_rulesets_that_filter_input():
    for name, ruleset in FILTERING.items():
        verdict, _ = _iptables_verdict(_evidence(nft=_cr(stdout=ruleset)))
        assert verdict == 'FILTERED_BY_NFTABLES', name


def test_rulesets_that_do_not_filter_input_keep_open():
    for name, ruleset in NOT_FILTERING.items():
        verdict, _ = _iptables_verdict(_evidence(nft=_cr(stdout=ruleset)))
        assert verdict == 'OPEN', name


def test_empty_nftables_ruleset_keeps_open():
    verdict, _ = _iptables_verdict(_evidence(nft=_cr(stdout='')))
    assert verdict == 'OPEN'


def test_legacy_warning_in_stdout_is_not_determined():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(stdout=''), iptables=OPEN_VIEW + '\n' + LEGACY_WARNING))
    assert verdict == 'UNKNOWN'
    assert 'iptables-legacy tables are present' in ctx['reason']


def test_legacy_warning_in_stderr_is_not_determined():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(stdout=''), iptables_stderr=LEGACY_WARNING))
    assert verdict == 'UNKNOWN'
    assert 'iptables-legacy -S' in ctx['reason']


def test_unreadable_nftables_keeps_open_and_says_so():
    verdict, ctx = _iptables_verdict(_evidence(nft=_cr(exit_code=1)))
    assert verdict == 'OPEN'
    assert ctx['nftables_checked'] is False


def test_filtered_iptables_view_is_unchanged():
    verdict, _ = _iptables_verdict(_evidence(nft=_cr(stdout=''), iptables='-P INPUT DROP'))
    assert verdict == 'FILTERED'


# --- findings ------------------------------------------------------------------

def _fake(nft_stdout, iptables_stdout=OPEN_VIEW, version='iptables v1.8.10 (nf_tables)', nft_exit=0):
    responses = {'command -v ufw': '', 'nft list ruleset': nft_stdout, 'iptables -S': iptables_stdout}
    exit_codes = {'command -v ufw': 127, 'nft list ruleset': nft_exit, 'iptables -S': 0}
    if version is not None:
        responses['iptables -V'] = version
        exit_codes['iptables -V'] = 0
    return ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)


def _iptables_finding(result):
    [finding] = [f for f in result['findings'] if 'iptables' in f['title'].lower()]
    return finding


def test_live_case_is_ok_and_names_the_chain():
    finding = _iptables_finding(audit_firewall(_fake(NATIVE_DROP)))
    assert finding['severity'] == 'ok'
    assert 'filtered by nftables' in finding['title']
    assert 'inet filter input' in finding['detail']
    assert 'nf_tables' in finding['detail']


def test_open_everywhere_is_still_high_and_names_the_backend():
    finding = _iptables_finding(audit_firewall(_fake('')))
    assert finding['severity'] == 'high'
    assert finding['id'] == 'FW-IPT-001'
    assert 'nf_tables' in finding['detail']


def test_legacy_backend_is_named():
    finding = _iptables_finding(audit_firewall(_fake('', version='iptables v1.8.7 (legacy)')))
    assert finding['severity'] == 'high'
    assert 'legacy' in finding['detail']


def test_unknown_backend_changes_nothing():
    finding = _iptables_finding(audit_firewall(_fake('', version=None)))
    assert finding['severity'] == 'high'
    assert 'nf_tables' not in finding['detail'] and 'legacy' not in finding['detail']


def test_legacy_tables_give_fw_ipt_002():
    finding = _iptables_finding(audit_firewall(_fake('', iptables_stdout=OPEN_VIEW + '\n' + LEGACY_WARNING)))
    assert finding['severity'] == 'low'
    assert finding['id'] == 'FW-IPT-002'
    assert finding.get('requires_manual_verification') is True


def test_unreadable_nftables_high_says_it_was_not_checked():
    finding = _iptables_finding(audit_firewall(_fake('', nft_exit=1)))
    assert finding['severity'] == 'high'
    assert 'nftables ruleset could not be read' in finding['detail']


# --- evidence ------------------------------------------------------------------

def test_sudo_helper_keeps_stderr():
    from netaudit_pkg.firewall_config import collect_iptables_live

    fake = ExitCodeFakeSSHExecutor(responses={'iptables -S': OPEN_VIEW}, exit_codes={'iptables -S': 0},
                                   stderrs={'iptables -S': LEGACY_WARNING})
    assert collect_iptables_live(fake).stderr == LEGACY_WARNING


def test_iptables_version_is_collected_without_sudo():
    from netaudit_pkg.firewall_config import collect_firewall_config

    fake = _fake('')
    evidence = collect_firewall_config(fake)
    assert evidence.iptables_version.stdout == 'iptables v1.8.10 (nf_tables)'
    [cmd] = [c for c in fake.calls if 'iptables -V' in c]
    assert 'sudo' not in cmd
