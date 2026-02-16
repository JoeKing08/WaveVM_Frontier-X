#!/usr/bin/env bash
set -euo pipefail

# Collect soak metrics from 5-node hierarchical Mode-B cluster.
# Required env:
#   WVM_HOST=js1.blockelite.cn
#   WVM_PORTS=26136,26132,26028,26124,26024
#   WVM_PASSWORDS=p0,p1,p2,p3,p4
# Optional:
#   ROUNDS=20
#   SLEEP_SEC=30
#   OUT=/tmp/wvm5_hier_long.csv

HOST="${WVM_HOST:-}"
IFS=',' read -r -a PORTS <<< "${WVM_PORTS:-}"
IFS=',' read -r -a PASSES <<< "${WVM_PASSWORDS:-}"
NODE_IDS=(0 1 2 3 4)
ROUNDS="${ROUNDS:-20}"
SLEEP_SEC="${SLEEP_SEC:-30}"
OUT="${OUT:-/tmp/wvm5_hier_long_$(date +%Y%m%d-%H%M%S).csv}"

if [[ -z "${HOST}" ]]; then
  echo "[ERROR] WVM_HOST is required"
  exit 1
fi
if [[ "${#PORTS[@]}" -ne 5 || "${#PASSES[@]}" -ne 5 ]]; then
  echo "[ERROR] WVM_PORTS/WVM_PASSWORDS must each contain 5 comma-separated entries"
  exit 1
fi

authfile() {
  local pass="$1" port="$2" f="/tmp/askpass_wvm_${port}.sh"
  cat > "${f}" <<EOF
#!/bin/sh
echo '${pass}'
EOF
  chmod 700 "${f}"
  echo "${f}"
}

printf 'ts_bjt,node,ssh_ok,tmux_g,tmux_x,tmux_m,tmux_s,gw_proc,master_proc,slave_proc,neighbors,congestion,bind_errs\n' > "${OUT}"

for _ in $(seq 1 "${ROUNDS}"); do
  ts="$(TZ=Asia/Shanghai date '+%F %T')"
  for i in "${!NODE_IDS[@]}"; do
    id="${NODE_IDS[$i]}"
    port="${PORTS[$i]}"
    pass="${PASSES[$i]}"
    a="$(authfile "${pass}" "${port}")"

    cmd="g=0;x=0;m=0;s=0; \
      tmux ls 2>/dev/null | grep -q wvm5g_${id} && g=1; \
      tmux ls 2>/dev/null | grep -q wvm5x_${id} && x=1; \
      tmux ls 2>/dev/null | grep -q wvm5m_${id} && m=1; \
      tmux ls 2>/dev/null | grep -q wvm5s_${id} && s=1; \
      gp=\$(pgrep -fc wavevm_gateway || echo 0); \
      mp=\$(pgrep -fc wavevm_node_master || echo 0); \
      sp=\$(pgrep -fc wavevm_node_slave || echo 0); \
      n=\$(grep -c 'New neighbor discovered' /tmp/wvm_master_${id}.log 2>/dev/null || echo 0); \
      c=\$(grep -c 'Severe Congestion' /tmp/wvm_master_${id}.log 2>/dev/null || echo 0); \
      b=\$(grep -ch 'bind failed\\|FATAL: Control plane bind failed' /tmp/wvm_sidecar_${id}.log /tmp/wvm_extra_${id}.log 2>/dev/null | awk '{s+=\$1} END{print s+0}'); \
      echo \"\$g,\$x,\$m,\$s,\$gp,\$mp,\$sp,\$n,\$c,\$b\""

    if row=$(DISPLAY=:0 SSH_ASKPASS="${a}" SSH_ASKPASS_REQUIRE=force setsid -w \
      ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -p "${port}" root@"${HOST}" "${cmd}" 2>/tmp/wvm5_ssh_${port}.err); then
      echo "${ts},${id},1,${row}" >> "${OUT}"
    else
      echo "${ts},${id},0,0,0,0,0,0,0,0,0,0,0" >> "${OUT}"
    fi
  done
  sleep "${SLEEP_SEC}"
done

echo "${OUT}"
