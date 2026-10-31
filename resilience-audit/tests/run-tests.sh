#!/usr/bin/env bash
# Offline tests for rn-resilience-audit.sh: fake system commands + a fixture root.
# Two scenarios ("bad" box, "good" box) with expected findings and exit codes.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
AUDIT="$HERE/../rn-resilience-audit.sh"
WORK=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT
PASSN=0; FAILN=0
ok()  { PASSN=$((PASSN+1)); }
bad() { FAILN=$((FAILN+1)); echo "  FAIL: $*"; }
expect()    { grep -qF -- "$2" "$1" && ok || bad "missing: $2"; }
expect_no() { grep -qF -- "$2" "$1" && bad "unexpected: $2" || ok; }
expect_re() { grep -qE -- "$2" "$1" && ok || bad "missing /$2/"; }

make_bin() {  # fake commands; behaviour selected by $SCEN
  local B="$1"; mkdir -p "$B"
  cat > "$B/id" <<'EOF'
#!/bin/bash
[ "$1" = -u ] && { echo 0; exit 0; }; exec /usr/bin/id "$@"
EOF
  cat > "$B/systemctl" <<'EOF'
#!/bin/bash
case "$1" in
  is-active)
    case "$SCEN:$2" in good:certbot.timer|good:logrotate.timer|*:nginx.service) echo active ;; *) echo inactive; exit 3 ;; esac ;;
  is-enabled)
    case "$SCEN:$2" in good:docker.service) echo enabled ;; *) echo disabled; exit 1 ;; esac ;;
  list-units)
    if [[ "$*" == *failed* ]]; then [ "$SCEN" = bad ] && echo "backup.service loaded failed failed Nightly backup"
    else echo "nginx.service loaded active running nginx"; echo "app.service loaded active running app"; fi ;;
  show)
    if [[ "$*" == *RuntimeWatchdogUSec* ]]; then [ "$SCEN" = bad ] && echo 0 || echo 1min; exit 0; fi
    if [ "$SCEN" = bad ]; then
      printf 'Restart=always\nNRestarts=5\nStartLimitIntervalUSec=0\nId=app.service\n\nId=nginx.service\nNRestarts=0\nRestart=no\nStartLimitIntervalUSec=10s\n'
    else
      printf 'Id=app.service\nNRestarts=0\nRestart=on-failure\nStartLimitIntervalUSec=10s\n\nId=nginx.service\nNRestarts=1\nRestart=no\nStartLimitIntervalUSec=10s\n'
    fi ;;
esac
EOF
  cat > "$B/docker" <<'EOF'
#!/bin/bash
case "$1" in
  info) exit 0 ;;
  ps) if [[ "$*" == *-q* ]]; then echo abc123; else echo "web 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp"; echo "db 127.0.0.1:5432->5432/tcp"; fi ;;
  inspect) [ "$SCEN" = bad ] && echo "/web no" || echo "/web unless-stopped" ;;
esac
EOF
  cat > "$B/iptables" <<'EOF'
#!/bin/bash
if [ "$2" = DOCKER-USER ]; then
  echo "-N DOCKER-USER"; [ "$SCEN" = good ] && echo "-A DOCKER-USER -i eth0 ! -s 10.0.0.0/24 -j DROP"; echo "-A DOCKER-USER -j RETURN"
elif [ "$2" = INPUT ]; then
  echo "-P INPUT ACCEPT"; echo "-A INPUT -i lo -j ACCEPT"; echo "-A INPUT -p tcp --dport 22 -j ACCEPT"; echo "-A INPUT -j DROP"
fi
EOF
  cat > "$B/journalctl" <<'EOF'
#!/bin/bash
echo "Oct 31 10:00:00 host kernel: boot ok"
[ "$SCEN" = bad ] && { echo "Oct 30 kernel: Out of memory: Killed process 123 (java)"; echo "Oct 29 kernel: oom-kill:constraint=CONSTRAINT_NONE"; }
exit 0
EOF
  cat > "$B/resolvectl" <<'EOF'
#!/bin/bash
echo "Global:"; [ "$SCEN" = bad ] && echo "Link 2 (eth0): 10.0.0.49" || echo "Link 2 (eth0): 10.0.0.49 1.1.1.1"
EOF
  cat > "$B/timedatectl" <<'EOF'
#!/bin/bash
[ "$SCEN" = bad ] && echo no || echo yes
EOF
  cat > "$B/df" <<'EOF'
#!/bin/bash
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
if [[ "$*" == *-i* ]]; then [ "$SCEN" = bad ] && echo "/dev/sda1 100 85 15 85% /" || echo "/dev/sda1 100 10 90 10% /"
else [ "$SCEN" = bad ] && echo "/dev/sda1 100 92 8 92% /" || echo "/dev/sda1 100 40 60 40% /"; fi
EOF
  cat > "$B/logrotate" <<'EOF'
#!/bin/bash
exit 0
EOF
  chmod +x "$B"/*
}

make_root() {  # fixture filesystem for scenario $1
  local S="$1" RT="$2" days
  mkdir -p "$RT/run/systemd/system" "$RT/etc/letsencrypt/live/example.com" "$RT/etc/letsencrypt/renewal" \
           "$RT/etc/nginx/sites-enabled" "$RT/etc/nginx/sites-available" "$RT/etc/logrotate.d" "$RT/etc/ufw" "$RT/var/log" "$RT/etc/systemd/system" "$RT/dev" "$RT/etc/cron.daily"
  [ "$S" = bad ] && days=5 || days=60
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=example.com -days "$days" \
    -keyout "$WORK/key.pem" -out "$RT/etc/letsencrypt/live/example.com/cert.pem" >/dev/null 2>&1
  echo "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;" > "$RT/etc/nginx/sites-enabled/site"
  echo "ENABLED=yes" > "$RT/etc/ufw/ufw.conf"
  if [ "$S" = bad ]; then
    printf '[renewalparams]\nauthenticator = webroot\n' > "$RT/etc/letsencrypt/renewal/example.com.conf"
    truncate -s 2G "$RT/var/log/app.log"; truncate -s 200M "$RT/var/log/worker.log"; truncate -s 150M "$RT/var/log/other.log"
    truncate -s 200M "$RT/var/log/worker.log.1"; mkdir -p "$RT/var/log/journal/abc"; truncate -s 300M "$RT/var/log/journal/abc/system.journal"
    printf '/var/log/worker.log\n/var/log/nothing/*.log {\n  daily\n}\n' > "$RT/etc/logrotate.d/worker"
    mkdir -p "$RT/etc/letsencrypt/live/stale.example"
    openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=stale.example -days 1 -keyout "$WORK/key2.pem" -out "$RT/etc/letsencrypt/live/stale.example/cert.pem" >/dev/null 2>&1
    echo "ssl_certificate /etc/letsencrypt/live/stale.example/fullchain.pem;" > "$RT/etc/nginx/sites-available/old-site"
    mkdir -p "$RT/var/run"; : > "$RT/var/run/reboot-required"
    : > "$RT/dev/watchdog"
  else
    printf '[renewalparams]\nauthenticator = nginx\ninstaller = nginx\n' > "$RT/etc/letsencrypt/renewal/example.com.conf"
  fi
}

run_scenario() {
  local S="$1" RT="$WORK/root-$1" BIN="$WORK/bin" OUT="$WORK/out-$1.txt" rc
  make_root "$S" "$RT"
  SCEN="$S" RN_AUDIT_ROOT="$RT" PATH="$BIN:$PATH" bash "$AUDIT" --no-color > "$OUT" 2>&1; rc=$?
  echo "$OUT|$rc"
}

make_bin "$WORK/bin"

echo "== scenario: bad box"
r=$(run_scenario bad); OUT=${r%|*}; RC=${r#*|}
[ "$RC" = 2 ] && ok || bad "bad box exit $RC, want 2"
expect_re "$OUT" "^\\[FAIL\\] TLS +Certificate 'example.com' expires in [45] days"
expect "$OUT" "[FAIL] TLS      Certificates are in use but no renewal timer or cron job is active"
expect "$OUT" "[WARN] TLS      Renewal for 'example.com' has no reload hook"
expect "$OUT" "[WARN] DOCKER   UFW is on, but Docker-published ports bypass UFW rules:"
expect "$OUT" "- web 0.0.0.0:8080->80/tcp"
expect_no "$OUT" "- db 127.0.0.1:5432"
expect "$OUT" "[WARN] DOCKER   Container web has no restart policy"
expect "$OUT" "[WARN] DOCKER   Docker is not enabled at boot"
expect "$OUT" "[FAIL] DISK     / is 92% full"
expect "$OUT" "[WARN] DISK     / has used 85% of its inodes"
expect "$OUT" "[FAIL] LOGS     /var/log/app.log is 2048 MB and no logrotate rule covers it"
expect "$OUT" "[WARN] LOGS     /var/log/other.log is 150 MB and no logrotate rule covers it"
expect "$OUT" "[INFO] LOGS     Large but covered by logrotate: /var/log/worker.log (200 MB)"
expect_no "$OUT" "worker.log.1"
expect_no "$OUT" "system.journal"
expect "$OUT" "[INFO] TLS      Certificate 'stale.example' (expires in"
expect "$OUT" "is not used by a running nginx/apache/haproxy"
expect_no "$OUT" "'stale.example' expires in"
expect "$OUT" "[FAIL] LOGS     logrotate is installed but not scheduled"
expect "$OUT" "[WARN] MEMORY   Kernel OOM killer fired 2 time(s) in the last 7 days"
expect "$OUT" "[FAIL] SERVICES backup.service has failed"
expect "$OUT" "[WARN] SERVICES app.service has been restarted automatically 5 times"
expect "$OUT" "[WARN] SERVICES app.service restarts on failure with no start limit"
expect_no "$OUT" "nginx.service has been restarted"
expect "$OUT" "[WARN] REBOOT   A reboot is pending"
expect "$OUT" "[PASS] REBOOT   Firewall rules (3 INPUT rules) are restored at boot"
expect "$OUT" "[WARN] DNS      Only one upstream DNS server (10.0.0.49)"
expect "$OUT" "[FAIL] TIME     Clock is not NTP-synchronised"
expect "$OUT" "[INFO] WATCHDOG Hardware watchdog device present but systemd is not using it"

echo "== scenario: good box"
r=$(run_scenario good); OUT=${r%|*}; RC=${r#*|}
[ "$RC" = 0 ] && ok || { bad "good box exit $RC, want 0"; grep -E '^\[(WARN|FAIL)\]' "$OUT"; }
expect_re "$OUT" "^\\[PASS\\] TLS +Certificate 'example.com' valid for (59|60) more days"
expect "$OUT" "[PASS] TLS      Automatic renewal timer is active"
expect_no "$OUT" "no reload hook"
expect "$OUT" "[PASS] DOCKER   Published container ports are filtered by 1 DOCKER-USER rule(s)"
expect "$OUT" "[PASS] DISK     All filesystems below 80% space and inode use"
expect "$OUT" "[PASS] LOGS     logrotate is scheduled"
expect "$OUT" "[PASS] LOGS     No active log file under /var/log is over 100 MB"
expect "$OUT" "[PASS] MEMORY   No out-of-memory kills"
expect "$OUT" "[PASS] SERVICES No failed services"
expect "$OUT" "[PASS] DNS      2 upstream DNS servers configured"
expect "$OUT" "[PASS] TIME     Clock is NTP-synchronised"
expect "$OUT" "[INFO] WATCHDOG No hardware watchdog device"

echo "== scenario: edge box (no UFW, DOCKER-USER rules, expired unused cert)"
RT="$WORK/root-edge"; make_root good "$RT"; rm -f "$RT/etc/ufw/ufw.conf"
mkdir -p "$RT/etc/letsencrypt/live/old.example"
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=old.example -days 1 -keyout "$WORK/k3.pem" -out "$RT/etc/letsencrypt/live/old.example/cert.pem" >/dev/null 2>&1
OUT="$WORK/out-edge.txt"
SCEN=good RN_AUDIT_ROOT="$RT" RN_AUDIT_NOW=$(( $(date +%s) + 10*86400 )) PATH="$WORK/bin:$PATH" bash "$AUDIT" --no-color > "$OUT" 2>&1
expect "$OUT" "[PASS] DOCKER   Published container ports are filtered by 1 DOCKER-USER rule(s)"
expect_no "$OUT" "Container ports published on all interfaces"
expect_re "$OUT" "Certificate 'old.example' \\(expired (8|9) days ago\\) is not used"
expect_no "$OUT" "expires in -"

echo "== passed $PASSN, failed $FAILN"
[ "$FAILN" = 0 ]
