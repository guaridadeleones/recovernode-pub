#!/usr/bin/env bash
# RecoverNode Linux Resilience Audit
# Read-only: changes nothing, writes no files, sends nothing over the network.
# Run as root for complete results:  sudo bash rn-resilience-audit.sh
# Copyright (c) 2026 RecoverNode. MIT License (see LICENSE).

set -u
VERSION="0.1.2"
SITE="https://www.recovernode.com"
R="${RN_AUDIT_ROOT:-}"          # filesystem prefix, used only by the test suite
NOW="${RN_AUDIT_NOW:-$(date +%s)}"

COLOR=1
for a in "$@"; do
  case "$a" in
    --no-color) COLOR=0 ;;
    --version) echo "rn-resilience-audit $VERSION"; exit 0 ;;
    -h|--help)
      echo "Usage: sudo bash rn-resilience-audit.sh [--no-color]"
      echo "Read-only audit of common Linux failure modes. Exit: 0 ok, 1 warnings, 2 failures."
      exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 64 ;;
  esac
done
[ -t 1 ] || COLOR=0

N_PASS=0; N_WARN=0; N_FAIL=0; N_INFO=0; N_SKIP=0
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
have() { command -v "$1" >/dev/null 2>&1; }
SYSTEMD=0; { [ -d "$R/run/systemd/system" ] || [ -n "${RN_AUDIT_FORCE_SYSTEMD:-}" ]; } && have systemctl && SYSTEMD=1

paint() { if [ "$COLOR" = 1 ]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi; }
# emit LEVEL AREA MESSAGE [FIX] [GUIDE-PATH]
emit() {
  local lvl="$1" area="$2" msg="$3" fix="${4:-}" guide="${5:-}" tag
  case "$lvl" in
    PASS) N_PASS=$((N_PASS+1)); tag=$(paint 32 "[PASS]") ;;
    WARN) N_WARN=$((N_WARN+1)); tag=$(paint 33 "[WARN]") ;;
    FAIL) N_FAIL=$((N_FAIL+1)); tag=$(paint 31 "[FAIL]") ;;
    INFO) N_INFO=$((N_INFO+1)); tag=$(paint 36 "[INFO]") ;;
    SKIP) N_SKIP=$((N_SKIP+1)); tag=$(paint 90 "[SKIP]") ;;
  esac
  printf '%s %-8s %s\n' "$tag" "$area" "$msg"
  [ -n "$fix" ] && printf '                Fix: %s\n' "$fix"
  [ -n "$guide" ] && printf '                Guide: %s%s\n' "$SITE" "$guide"
  return 0
}
unit_active()  { [ "$SYSTEMD" = 1 ] && [ "$(systemctl is-active "$1" 2>/dev/null)" = active ]; }
unit_enabled() { [ "$SYSTEMD" = 1 ] && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]; }
running() {  # running SERVICE PROCESS
  if [ "$SYSTEMD" = 1 ]; then unit_active "$1.service"; else have pgrep && pgrep -x "$2" >/dev/null 2>&1; fi
}
# config files that a *running* web server actually loads (not sites-available, not leftovers)
active_web_configs() {
  local f
  if running nginx nginx; then
    for f in "$R"/etc/nginx/nginx.conf "$R"/etc/nginx/conf.d/*.conf "$R"/etc/nginx/sites-enabled/*; do [ -e "$f" ] && echo "$f"; done
  fi
  if running apache2 apache2 || running httpd httpd; then
    for f in "$R"/etc/apache2/sites-enabled/* "$R"/etc/apache2/conf-enabled/* "$R"/etc/httpd/conf/*.conf "$R"/etc/httpd/conf.d/*.conf; do [ -e "$f" ] && echo "$f"; done
  fi
  if running haproxy haproxy; then [ -e "$R/etc/haproxy/haproxy.cfg" ] && echo "$R/etc/haproxy/haproxy.cfg"; fi
}

G_TLS=/resources/ssl-certificate-monitoring
G_SVC=/resources/systemd-service-monitoring
G_HEALTH=/resources/linux-server-health-monitoring
G_DNS=/resources/dns-monitoring-troubleshooting
G_REC=/resources/linux-server-recovery

echo "RecoverNode Linux Resilience Audit v$VERSION  (read-only; nothing is changed or uploaded)"
echo "Host: $(hostname 2>/dev/null)  Kernel: $(uname -r)  Time: $(date -u -d "@$NOW" +%FT%TZ)  Root: $([ $IS_ROOT = 1 ] && echo yes || echo 'no (some checks skipped)')"
echo

# ---------------------------------------------------------------- TLS
check_tls() {
  local le="$R/etc/letsencrypt" live d name cert end epoch days ref anyref=0 conf hooks=0
  [ -d "$le/live" ] || { emit INFO TLS "No Let's Encrypt certificates found under /etc/letsencrypt (other certificate setups are not checked)"; return; }
  [ -r "$le/live" ] && [ -x "$le/live" ] || { emit SKIP TLS "Certificates present but not readable; run as root"; return; }
  have openssl || { emit SKIP TLS "openssl not installed"; return; }
  local -a cfgs=(); mapfile -t cfgs < <(active_web_configs)
  for d in "$le"/live/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d"); cert="$d/cert.pem"
    [ -r "$cert" ] || continue
    end=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
    epoch=$(date -d "$end" +%s 2>/dev/null) || continue
    days=$(( (epoch - NOW) / 86400 ))
    ref=0
    [ "${#cfgs[@]}" -gt 0 ] && grep -qsF -- "/etc/letsencrypt/live/$name/" "${cfgs[@]}" 2>/dev/null && { ref=1; anyref=1; }
    if [ "$ref" = 0 ]; then
      emit INFO TLS "Certificate '$name' ($([ "$days" -lt 0 ] && echo "expired $(( -days )) days ago" || echo "expires in $days days")) is not used by a running nginx/apache/haproxy (only enabled configs are checked)"
    elif [ "$days" -lt 0 ]; then
      emit FAIL TLS "Certificate '$name' EXPIRED $(( -days )) days ago and is in use" "certbot renew, then reload the web server" "$G_TLS"
    elif [ "$days" -lt 7 ]; then
      emit FAIL TLS "Certificate '$name' expires in $days days" "certbot renew --dry-run to find why renewal is not happening" "$G_TLS"
    elif [ "$days" -lt 21 ]; then
      emit WARN TLS "Certificate '$name' expires in $days days (renewal normally happens at 30 days)" "certbot renew --dry-run" "$G_TLS"
    else
      emit PASS TLS "Certificate '$name' valid for $days more days"
    fi
  done
  # renewal scheduler
  if unit_active certbot.timer || unit_active snap.certbot.renew.timer; then
    emit PASS TLS "Automatic renewal timer is active"
  elif [ "$anyref" = 1 ]; then
    if grep -lsE 'certbot.*renew' "$R"/etc/cron.d/* "$R"/var/spool/cron/crontabs/* 2>/dev/null | xargs -r grep -LsF '/run/systemd/system' 2>/dev/null | grep -q .; then
      emit PASS TLS "Renewal runs from cron"
    else
      emit FAIL TLS "Certificates are in use but no renewal timer or cron job is active" "systemctl enable --now certbot.timer (or snap.certbot.renew.timer)" "$G_TLS"
    fi
  fi
  # does a renewed certificate get loaded?
  ls -A "$le"/renewal-hooks/deploy "$le"/renewal-hooks/post 2>/dev/null | grep -q . && hooks=1
  for conf in "$le"/renewal/*.conf; do
    [ -r "$conf" ] || continue
    name=$(basename "$conf" .conf)
    if grep -qE '^\s*installer\s*=\s*(nginx|apache)' "$conf" || grep -qE '^\s*(renew_hook|deploy_hook|post_hook)\s*=' "$conf" || [ "$hooks" = 1 ]; then
      :
    else
      emit WARN TLS "Renewal for '$name' has no reload hook; a renewed certificate is not served until the web server reloads" "add a deploy hook, e.g. /etc/letsencrypt/renewal-hooks/deploy/reload-nginx running: systemctl reload nginx" "$G_TLS"
    fi
  done
}

# ---------------------------------------------------------------- Docker / firewall
check_docker() {
  have docker || return 0
  docker info >/dev/null 2>&1 || { emit SKIP DOCKER "Docker installed but $([ "$IS_ROOT" = 1 ] && echo 'the daemon is not reachable (not running?)' || echo 'not accessible; run as root')"; return; }
  local ports ufw_on=0 custom=0 line n p ids
  ports=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '(0\.0\.0\.0|\[::\]|:::):[0-9]+' || true)
  { [ -r "$R/etc/ufw/ufw.conf" ] && grep -qE '^ENABLED=yes' "$R/etc/ufw/ufw.conf"; } && ufw_on=1
  if [ -n "$ports" ]; then
    if [ "$IS_ROOT" = 1 ] && have iptables; then
      custom=$(iptables -S DOCKER-USER 2>/dev/null | grep -E '^-A DOCKER-USER' | grep -vcE '^-A DOCKER-USER -j RETURN$')
    fi
    if [ "${custom:-0}" -gt 0 ]; then
      emit PASS DOCKER "Published container ports are filtered by $custom DOCKER-USER rule(s) (review them)"
    elif [ "$ufw_on" = 1 ]; then
      emit WARN DOCKER "UFW is on, but Docker-published ports bypass UFW rules:" "filter them in the DOCKER-USER iptables chain, or bind ports to 127.0.0.1/LAN addresses"
      while IFS= read -r line; do printf '                - %s\n' "$line"; done <<< "$ports"
    else
      emit INFO DOCKER "Container ports published on all interfaces:"
      while IFS= read -r line; do printf '                - %s\n' "$line"; done <<< "$ports"
    fi
  fi
  ids=$(docker ps -q 2>/dev/null)
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    while read -r n p; do
      case "$p" in no|"") emit WARN DOCKER "Container ${n#/} has no restart policy; it will stay down after a reboot or crash" "docker update --restart unless-stopped ${n#/}" "$G_REC" ;; esac
    done < <(docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $ids 2>/dev/null)
  fi
  if [ "$SYSTEMD" = 1 ] && ! unit_enabled docker.service && ! unit_enabled docker.socket && ! unit_enabled snap.docker.dockerd.service; then
    emit WARN DOCKER "Docker is not enabled at boot" "systemctl enable docker" "$G_REC"
  fi
}

# ---------------------------------------------------------------- storage / logs / memory
check_storage() {
  local fs pct mnt big huge any=0
  while read -r fs pct mnt; do
    pct=${pct%\%}; [ "$pct" -eq "$pct" ] 2>/dev/null || continue
    if   [ "$pct" -ge 90 ]; then emit FAIL DISK "$mnt is ${pct}% full ($fs)" "free space or grow the filesystem; full disks stop logging, databases and package updates" "$G_HEALTH"; any=1
    elif [ "$pct" -ge 80 ]; then emit WARN DISK "$mnt is ${pct}% full ($fs)" "find growth: du -xh --max-depth=2 $mnt | sort -h | tail" "$G_HEALTH"; any=1
    fi
  done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | awk 'NR>1{print $1, $5, $6}')
  while read -r fs pct mnt; do
    pct=${pct%\%}; [ "$pct" -eq "$pct" ] 2>/dev/null || continue
    if   [ "$pct" -ge 90 ]; then emit FAIL DISK "$mnt has used ${pct}% of its inodes" "usually millions of small files (sessions, cache, mail queue)" "$G_HEALTH"; any=1
    elif [ "$pct" -ge 80 ]; then emit WARN DISK "$mnt has used ${pct}% of its inodes" "" "$G_HEALTH"; any=1
    fi
  done < <(df -P -i -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | awk 'NR>1{print $1, $5, $6}')
  [ "$any" = 0 ] && emit PASS DISK "All filesystems below 80% space and inode use"

  if [ -d "$R/var/log" ]; then
    local -a pats=(); local size f p covered n_big=0 info_list=""
    mapfile -t pats < <(cat "$R/etc/logrotate.conf" "$R"/etc/logrotate.d/* 2>/dev/null | sed 's/#.*//' | tr -s ' \t' '\n' | sed 's/{$//' | grep '^/')
    while read -r size f; do
      [ -n "$f" ] || continue
      case "$f" in *.gz|*.xz|*.bz2|*.zst|*.old) continue ;; esac
      [[ "$f" =~ \.[0-9]+$ || "$f" =~ -[0-9]{8}$ ]] && continue          # already-rotated copies
      covered=0
      for p in "${pats[@]}"; do
        # shellcheck disable=SC2053
        [[ "$f" == $R$p ]] && { covered=1; break; }
      done
      n_big=$((n_big+1))
      if [ "$covered" = 0 ] && [ "$size" -gt 1073741824 ]; then
        emit FAIL LOGS "${f#"$R"} is $((size/1048576)) MB and no logrotate rule covers it" "add a rule in /etc/logrotate.d (copytruncate if the program keeps the file open)" "$G_HEALTH"
      elif [ "$covered" = 0 ]; then
        emit WARN LOGS "${f#"$R"} is $((size/1048576)) MB and no logrotate rule covers it" "add a rule in /etc/logrotate.d" "$G_HEALTH"
      else
        info_list="$info_list ${f#"$R"} ($((size/1048576)) MB)"
      fi
    done < <(find "$R/var/log" -xdev -path "$R/var/log/journal" -prune -o -type f -size +100M -printf '%s %p\n' 2>/dev/null)
    [ -n "$info_list" ] && emit INFO LOGS "Large but covered by logrotate:$info_list"
    [ "$n_big" = 0 ] && emit PASS LOGS "No active log file under /var/log is over 100 MB$([ $IS_ROOT = 0 ] && echo ' (unreadable directories skipped)')"
  fi
  if unit_active logrotate.timer || [ -x "$R/etc/cron.daily/logrotate" ]; then
    emit PASS LOGS "logrotate is scheduled"
  elif have logrotate; then
    emit FAIL LOGS "logrotate is installed but not scheduled (no active logrotate.timer or cron.daily job)" "systemctl enable --now logrotate.timer" "$G_HEALTH"
  else
    emit WARN LOGS "logrotate is not installed" "install logrotate" "$G_HEALTH"
  fi

  if have journalctl; then
    local oom
    if [ -n "$(journalctl -k -n 1 --no-pager -q 2>/dev/null)" ] && oom=$(journalctl -k --since "7 days ago" --no-pager -q 2>/dev/null); then
      oom=$(printf '%s\n' "$oom" | grep -cE 'Out of memory: Killed process|oom-kill:')
      if [ "$oom" -gt 0 ]; then emit WARN MEMORY "Kernel OOM killer fired $oom time(s) in the last 7 days" "find the process: journalctl -k --since '7 days ago' | grep -i 'killed process'" "$G_HEALTH"
      else emit PASS MEMORY "No out-of-memory kills in the last 7 days"; fi
    else
      emit SKIP MEMORY "Kernel log not available$([ "$IS_ROOT" = 0 ] && echo '; run as root')"
    fi
  fi
}

# ---------------------------------------------------------------- systemd services
check_services() {
  [ "$SYSTEMD" = 1 ] || { emit SKIP SERVICES "systemd not detected"; return; }
  local failed u units id nr rs sl
  failed=$(systemctl list-units --type=service --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')
  if [ -n "$failed" ]; then
    for u in $failed; do emit FAIL SERVICES "$u has failed" "journalctl -u $u -b --no-pager | tail -50" "$G_SVC"; done
  else
    emit PASS SERVICES "No failed services"
  fi
  units=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
  [ -n "$units" ] || return 0
  # shellcheck disable=SC2086
  while IFS='|' read -r id nr rs sl; do
    [ -n "$id" ] || continue
    if [ "${nr:-0}" -ge 3 ] 2>/dev/null; then
      emit WARN SERVICES "$id has been restarted automatically $nr times (it is flapping)" "journalctl -u $id --no-pager | grep -iE 'error|fail' | tail" "$G_SVC"
    fi
    if [ "$rs" != no ] && [ -n "$rs" ] && [ "$sl" = 0 ]; then
      emit WARN SERVICES "$id restarts on failure with no start limit; a broken service will restart forever" "set StartLimitIntervalSec and StartLimitBurst in a drop-in" "$G_SVC"
    fi
  done < <(systemctl show -p Id -p NRestarts -p Restart -p StartLimitIntervalUSec $units 2>/dev/null |
           awk -F= '/^Id=/{id=$2} /^NRestarts=/{nr=$2} /^Restart=/{rs=$2} /^StartLimitIntervalUSec=/{sl=$2} /^$/{if(id)print id"|"nr"|"rs"|"sl; id=nr=rs=sl=""} END{if(id)print id"|"nr"|"rs"|"sl}')
}

# ---------------------------------------------------------------- reboot survivability
check_reboot() {
  if [ -f "$R/var/run/reboot-required" ] || [ -f "$R/run/reboot-required" ]; then
    emit WARN REBOOT "A reboot is pending (updates installed but not active)" "schedule a reboot; until then the running kernel/libraries are the old ones" "$G_REC"
  elif have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; then
    emit WARN REBOOT "A reboot is pending (needs-restarting -r)" "" "$G_REC"
  else
    emit PASS REBOOT "No pending reboot detected"
  fi
  if [ "$IS_ROOT" = 1 ] && have iptables; then
    local n persisted=0
    n=$(iptables -S INPUT 2>/dev/null | grep -c '^-A INPUT')
    if [ "${n:-0}" -gt 0 ]; then
      { [ -r "$R/etc/ufw/ufw.conf" ] && grep -qE '^ENABLED=yes' "$R/etc/ufw/ufw.conf"; } && persisted=1
      unit_active firewalld.service && persisted=1
      unit_enabled netfilter-persistent.service && persisted=1
      unit_enabled iptables.service && persisted=1
      unit_enabled nftables.service && persisted=1
      grep -lsE '^\s*Exec(Start|StartPre)=.*(iptables|nft |ufw|firewall)' "$R"/etc/systemd/system/*.service 2>/dev/null | grep -q . && persisted=1
      if [ "$persisted" = 1 ]; then emit PASS REBOOT "Firewall rules ($n INPUT rules) are restored at boot"
      else emit WARN REBOOT "$n firewall INPUT rules are loaded but nothing restores them at boot" "save them with netfilter-persistent/iptables-persistent, ufw or nftables.service" "$G_REC"; fi
    fi
  fi
}

# ---------------------------------------------------------------- DNS / time
check_dns_time() {
  local servers count
  if have resolvectl && resolvectl dns >/dev/null 2>&1; then
    servers=$(resolvectl dns 2>/dev/null | cut -d: -f2- | tr ' ' '\n' | grep -E '^[0-9a-fA-F.:]+$' | grep -vE '^(127\.|::1$)' | sort -u)
  else
    servers=$(awk '/^nameserver/{print $2}' "$R/etc/resolv.conf" 2>/dev/null | grep -vE '^(127\.|::1$)' | sort -u)
  fi
  count=$(printf '%s\n' "$servers" | grep -c .)
  if   [ "$count" -eq 0 ]; then emit INFO DNS "No upstream DNS servers found (local resolver only?)"
  elif [ "$count" -eq 1 ]; then emit WARN DNS "Only one upstream DNS server ($servers); if it fails, name resolution fails" "add a second resolver, ideally on different infrastructure" "$G_DNS"
  else emit PASS DNS "$count upstream DNS servers configured"; fi

  local sync=""
  have timedatectl && sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if   [ "$sync" = yes ]; then emit PASS TIME "Clock is NTP-synchronised"
  elif [ "$sync" = no ];  then emit FAIL TIME "Clock is not NTP-synchronised (breaks TLS validation, log correlation and schedules)" "timedatectl set-ntp true (or enable chrony)" "$G_HEALTH"
  elif have chronyc && chronyc tracking 2>/dev/null | grep -q 'Leap status *: Normal'; then emit PASS TIME "Clock is synchronised (chrony)"
  else emit SKIP TIME "Could not determine time synchronisation"; fi
}

# ---------------------------------------------------------------- watchdog
check_watchdog() {
  if [ -e "$R/dev/watchdog" ] || [ -e "$R/dev/watchdog0" ]; then
    local rw=""; [ "$SYSTEMD" = 1 ] && rw=$(systemctl show -p RuntimeWatchdogUSec --value 2>/dev/null)
    case "$rw" in ""|0|infinity) emit INFO WATCHDOG "Hardware watchdog device present but systemd is not using it (a hung kernel will not reboot itself)" "set RuntimeWatchdogSec= in /etc/systemd/system.conf" "$G_REC" ;;
                 *) emit PASS WATCHDOG "Hardware watchdog in use by systemd ($rw)" ;; esac
  else
    emit INFO WATCHDOG "No hardware watchdog device (a hung kernel needs a manual power cycle)" "" "$G_REC"
  fi
}

check_tls; check_docker; check_storage; check_services; check_reboot; check_dns_time; check_watchdog

echo
echo "Summary: $N_FAIL fail, $N_WARN warn, $N_PASS pass, $N_INFO info, $N_SKIP skipped"
echo "Nothing was changed. Guides and a free fit assessment: $SITE"
if [ "$N_FAIL" -gt 0 ]; then exit 2; elif [ "$N_WARN" -gt 0 ]; then exit 1; else exit 0; fi
