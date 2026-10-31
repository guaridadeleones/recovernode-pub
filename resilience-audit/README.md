# RecoverNode Linux Resilience Audit

A free, read-only script that checks a Linux server for the failure modes that most often take self-hosted sites and services down quietly, and tells you how to fix each one.

- **Read-only.** It changes nothing, writes no files and makes no network connections.
- **One file, plain Bash.** Read it before you run it; it is about 300 lines.
- **Tested before release** on three real Linux servers (including Debian 12 on a Raspberry Pi) and by an offline test suite.
- **Graded findings.** Each result is PASS, WARN, FAIL, INFO or SKIP, with a one-line fix and, where one exists, a guide.

## Run it

```bash
curl -fsSLO https://raw.githubusercontent.com/guaridadeleones/recovernode-pub/main/resilience-audit/rn-resilience-audit.sh
less rn-resilience-audit.sh                     # read it first
sudo bash rn-resilience-audit.sh
```

You can run it without `sudo`, but checks that need root (certificates, the firewall, the kernel log) will show as SKIP.

Exit codes: `0` everything passed, `1` warnings, `2` failures. Add `--no-color` when piping the output to a file.

## What it checks

| Area | Check |
|---|---|
| TLS | Let's Encrypt certificates that are in use by nginx, Apache or HAProxy and expire within 21 days (WARN) or 7 days (FAIL); renewal timer or cron job inactive; renewals with no reload hook (the new certificate is not served until the web server reloads) |
| Docker | Container ports published on all interfaces while UFW is on (Docker-published ports bypass UFW unless you filter them in `DOCKER-USER`); containers with no restart policy; Docker not enabled at boot |
| Disk | Filesystems at or above 80% / 90% space or inode use |
| Logs | Files over 100 MB / 1 GB under `/var/log`; logrotate installed but not scheduled |
| Memory | Kernel OOM-killer events in the last 7 days |
| Services | Failed systemd services; services restarted automatically 3 or more times (flapping); services that restart on failure with the start limit disabled |
| Reboot | Pending reboot after updates; firewall rules loaded but not restored at boot |
| DNS | Only one upstream resolver |
| Time | Clock not NTP-synchronised |
| Watchdog | Hardware watchdog present but not used by systemd |

It does **not** check security hardening, backups, application health or anything outside the machine it runs on.

## Verify that it is read-only

```bash
sudo strace -f -qq -e trace=openat,unlinkat,renameat2,mkdirat -o /tmp/audit.trace bash rn-resilience-audit.sh
grep -E 'O_WRONLY|O_RDWR|O_CREAT|unlinkat|renameat|mkdirat' /tmp/audit.trace | grep -v /dev/
```

The second command should print nothing. (`strace` itself writes `/tmp/audit.trace`; the audit writes nothing.)

## Tests

`tests/run-tests.sh` runs the audit offline against fake system commands and a fixture filesystem, in two scenarios (a broken server and a healthy one), and checks every expected finding and exit code.

## About

Built by [RecoverNode](https://www.recovernode.com), which does self-hosted, full-path Linux monitoring with guarded local recovery. The guides linked from the findings are on [recovernode.com/resources](https://www.recovernode.com).

MIT License, see `LICENSE`.
