"""
Kernel sysctl collection and parsing: the single place that runs `sysctl -a`
over SSH and turns its output into a structured KernelConfig.

Unlike nginx_config.py and ssh_config.py, there is no Include-precedence or
comment-stripping problem here at all: `sysctl -a` prints the kernel's own
current runtime value straight from /proc/sys/ for every key, one
`key = value` per line, never the contents of /etc/sysctl.conf or
/etc/sysctl.d/*.conf. This was confirmed empirically on a live VM before
this module was written (docs/checks/kernel_hardening.md section 2): the
VM's /etc/sysctl.d/ contained no .conf files at all (only the stock
README.sysctl) and /etc/sysctl.conf was empty, so there was nothing to
resolve - but the "runtime value only, never re-parse drop-ins" behavior is
documented kernel behavior, not a VM-specific coincidence, so this collector
deliberately never reads /etc/sysctl.conf or /etc/sysctl.d/ itself.

`sysctl -a` requires root for a *complete* error-free read: confirmed
empirically on the same VM - without sudo, `sysctl -a` returned 1084 lines
with 3 `permission denied` errors, all on `kernel.apparmor_*` keys (outside
this module's scope regardless, see docs/checks/kernel_hardening.md section
1). With `sudo -S sysctl -a`, 1081 lines, 0 permission-denied errors. All 16
keys this collector actually reads happened to be unrestricted even without
sudo on that VM - but this collector always uses ssh.sudo() anyway,
deliberately not relying on "these particular keys are unrestricted today"
holding true on every future host (same reasoning ssh_config.py's `sshd -T`
docstring gives for its own unconditional ssh.sudo() use).

Deliberately data-only and deliberately narrow: KernelConfig holds only the
16 fields docs/checks/kernel_hardening.md's spec actually scores, plus
`kernel_version` as a separately-collected informational field (`uname -r`,
not a sysctl key at all). This is not a general-purpose sysctl dump - fields
outside the current spec (e.g. `kernel.core_pattern`, `perf_event_paranoid`)
are deliberately not collected here; adding them "since sysctl -a already
has the data anyway" is exactly the scope creep the spec's section 1
explicitly rejected. A future module revision that needs a new field adds
it deliberately, with its own spec entry, not by default.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ssh import SSHExecutor

@dataclass
class KernelConfig:
    """Structured facts read from `sysctl -a` (runtime effective values)
    plus `uname -r`. Data only - no severity, no score, no opinion about
    whether a value is good or bad. That judgment belongs to the consumer
    (checks/kernel_hardening.py), not to this parser.

    Field types deliberately follow what `sysctl -a` actually prints for
    each key, not a simplified yes/no model:
      - randomize_va_space, kptr_restrict, yama_ptrace_scope, suid_dumpable,
        rp_filter_all, rp_filter_default are `int`, not `bool` - each has
        more than two effective values (0/1/2, or 0/1/2/3 for
        yama_ptrace_scope) that a hardening control needs to distinguish
        (see docs/checks/kernel_hardening.md sections 3.2/3.3/4.1/4.2/4.4 -
        collapsing kptr_restrict's 1-vs-2 or suid_dumpable's 0-vs-1-vs-2 to
        a bool would silently lose exactly the distinction those controls
        are built on).
      - Every other collected key is `bool` - each has exactly two
        meaningful runtime values (0/1) with no intermediate case, per the
        spec's section 3.1 binary-controls table.
      - `None` (for any field) means the key was absent from `sysctl -a`'s
        output or its value didn't parse as expected - never a guessed
        default. A hardening control seeing `None` treats it as unreadable
        for that field, exactly as `ssh_config.py`'s `_yes_no()` does for
        an sshd directive it can't parse.
    """

    readable: bool = False
    kernel_version: str = ''

    randomize_va_space: int | None = None
    dmesg_restrict: bool | None = None
    kptr_restrict: int | None = None
    yama_ptrace_scope: int | None = None
    suid_dumpable: int | None = None

    ip_forward: bool | None = None
    ipv6_forwarding: bool | None = None
    tcp_syncookies: bool | None = None
    icmp_echo_ignore_broadcasts: bool | None = None
    accept_source_route: bool | None = None
    accept_redirects: bool | None = None
    secure_redirects: bool | None = None
    send_redirects: bool | None = None
    log_martians: bool | None = None
    rp_filter_all: int | None = None
    rp_filter_default: int | None = None


def collect_kernel_config(ssh: SSHExecutor) -> KernelConfig:
    """Run `uname -r` and `sysctl -a` over the given (already-connected)
    SSH session and parse the result into a KernelConfig. Read-only -
    neither command changes anything on the target.

    `sysctl -a` runs via ssh.sudo(), not ssh.run() - see this module's
    docstring for why this is unconditional rather than "only if the VM
    needs it." `uname -r` needs no privilege and runs via plain ssh.run().
    """
    ver_out, _ = ssh.run('uname -r')
    kernel_version = ver_out.strip()

    out, err = ssh.sudo('sysctl -a')
    if not out.strip():
        return KernelConfig(readable=False, kernel_version=kernel_version)

    return _parse_sysctl_a(out, kernel_version=kernel_version)


def _parse_sysctl_a(output: str, kernel_version: str = '') -> KernelConfig:
    """Pure parsing, no I/O - split out from collect_kernel_config() so it
    can be unit-tested against fixture text without an SSH mock.

    `sysctl -a` prints one `key = value` per line (space-padded `=`,
    per-line, no continuation lines for any of the 16 keys this module
    reads). A small number of lines are `permission denied` errors instead
    of `key = value` (e.g. the VM's `kernel.apparmor_*` keys without sudo -
    docs/checks/kernel_hardening.md section 2) - those lines are silently
    skipped, same as any other line that doesn't match the `key = value`
    shape, rather than raising. This collector always requests sudo (see
    docstring), so a well-formed sudo session shouldn't produce any denied
    lines for the 16 keys it actually reads - but the parser doesn't assume
    that either; a key simply absent from `effective` becomes `None` in
    KernelConfig, not a crash.
    """
    effective: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # First occurrence wins, matching ssh_config.py's identical
        # precedent for defensive robustness against any key sysctl -a
        # might ever print more than once. None of the 16 keys this module
        # reads are known to repeat, so this only matters as a safety net.
        effective.setdefault(key, value)

    def _int(key: str) -> int | None:
        v = effective.get(key)
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    def _bool(key: str) -> bool | None:
        v = effective.get(key)
        if v == '0':
            return False
        if v == '1':
            return True
        return None

    return KernelConfig(
        readable=True,
        kernel_version=kernel_version,
        randomize_va_space=_int('kernel.randomize_va_space'),
        dmesg_restrict=_bool('kernel.dmesg_restrict'),
        kptr_restrict=_int('kernel.kptr_restrict'),
        yama_ptrace_scope=_int('kernel.yama.ptrace_scope'),
        suid_dumpable=_int('fs.suid_dumpable'),
        ip_forward=_bool('net.ipv4.ip_forward'),
        ipv6_forwarding=_bool('net.ipv6.conf.all.forwarding'),
        tcp_syncookies=_bool('net.ipv4.tcp_syncookies'),
        icmp_echo_ignore_broadcasts=_bool('net.ipv4.icmp_echo_ignore_broadcasts'),
        accept_source_route=_bool('net.ipv4.conf.all.accept_source_route'),
        accept_redirects=_bool('net.ipv4.conf.all.accept_redirects'),
        secure_redirects=_bool('net.ipv4.conf.all.secure_redirects'),
        send_redirects=_bool('net.ipv4.conf.all.send_redirects'),
        log_martians=_bool('net.ipv4.conf.all.log_martians'),
        rp_filter_all=_int('net.ipv4.conf.all.rp_filter'),
        rp_filter_default=_int('net.ipv4.conf.default.rp_filter'),
    )
