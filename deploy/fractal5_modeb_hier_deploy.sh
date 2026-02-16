#!/usr/bin/env bash
set -euo pipefail

# Deploy a 5-node hierarchical Mode-B cluster via password SSH + tmux.
# Required env:
#   WVM_HOST=js1.blockelite.cn
#   WVM_PORTS=26136,26132,26028,26124,26024
#   WVM_PASSWORDS=p0,p1,p2,p3,p4
# Optional env:
#   WVM_REMOTE_ROOT=/root/WaveVM_Frontier-X

HOST="${WVM_HOST:-}"
IFS=',' read -r -a PORTS <<< "${WVM_PORTS:-}"
IFS=',' read -r -a PASSES <<< "${WVM_PASSWORDS:-}"
NODE_IDS=(0 1 2 3 4)
REMOTE_ROOT="${WVM_REMOTE_ROOT:-/root/WaveVM_Frontier-X}"

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

run_ssh() {
  local pass="$1" port="$2" cmd="$3" a
  a="$(authfile "${pass}" "${port}")"
  DISPLAY=:0 SSH_ASKPASS="${a}" SSH_ASKPASS_REQUIRE=force setsid -w \
    ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "${port}" root@"${HOST}" "${cmd}"
}

echo "== deploy hierarchical fractal (5-node) =="
for i in "${!NODE_IDS[@]}"; do
  id="${NODE_IDS[$i]}"
  port="${PORTS[$i]}"
  pass="${PASSES[$i]}"

  SWARM_CONTENT='NODE 0 127.0.0.1 8804 1 1
NODE 1 127.0.0.1 8804 1 1
NODE 2 127.0.0.1 8804 1 1
NODE 3 127.0.0.1 8804 1 1
NODE 4 127.0.0.1 8804 1 1'

  if [[ "${id}" == "0" ]]; then
    SIDE='ROUTE 0 1 127.0.0.1 8800
ROUTE 1 1 '"${HOST}"' 26188
ROUTE 2 3 '"${HOST}"' 26196'
    SIDE_UP_IP='127.0.0.1'; SIDE_UP_PORT='8802'; EXTRA='childA'; EXTRA_CTRL=8812
  elif [[ "${id}" == "1" ]]; then
    SIDE='ROUTE 1 1 127.0.0.1 8800
ROUTE 0 1 '"${HOST}"' 26196
ROUTE 2 3 '"${HOST}"' 26196'
    SIDE_UP_IP="${HOST}"; SIDE_UP_PORT='26196'; EXTRA='none'; EXTRA_CTRL=0
  elif [[ "${id}" == "2" ]]; then
    SIDE='ROUTE 2 1 127.0.0.1 8800
ROUTE 3 1 '"${HOST}"' 26176
ROUTE 0 2 '"${HOST}"' 26084
ROUTE 4 1 '"${HOST}"' 26084'
    SIDE_UP_IP='127.0.0.1'; SIDE_UP_PORT='8802'; EXTRA='childB'; EXTRA_CTRL=8813
  elif [[ "${id}" == "3" ]]; then
    SIDE='ROUTE 3 1 127.0.0.1 8800
ROUTE 2 1 '"${HOST}"' 26084
ROUTE 0 2 '"${HOST}"' 26084
ROUTE 4 1 '"${HOST}"' 26084'
    SIDE_UP_IP="${HOST}"; SIDE_UP_PORT='26084'; EXTRA='none'; EXTRA_CTRL=0
  else
    SIDE='ROUTE 4 1 127.0.0.1 8800
ROUTE 0 4 127.0.0.1 8803'
    SIDE_UP_IP='127.0.0.1'; SIDE_UP_PORT='8803'; EXTRA='parent'; EXTRA_CTRL=8814
  fi

  run_ssh "${pass}" "${port}" "set -e
cd ${REMOTE_ROOT}
cat > /root/swarm5_hier.conf <<'SWARMEOF'
${SWARM_CONTENT}
SWARMEOF
cat > /root/sidecar_routes_${id}.txt <<'SIDEOF'
${SIDE}
SIDEOF

if [ '${EXTRA}' = 'childA' ]; then
cat > /root/extra_routes_${id}.txt <<'XEOF'
ROUTE 0 1 127.0.0.1 8800
ROUTE 1 1 ${HOST} 26188
ROUTE 2 3 ${HOST} 26079
XEOF
fi
if [ '${EXTRA}' = 'childB' ]; then
cat > /root/extra_routes_${id}.txt <<'XEOF'
ROUTE 2 1 127.0.0.1 8800
ROUTE 3 1 ${HOST} 26176
ROUTE 0 2 ${HOST} 26079
ROUTE 4 1 ${HOST} 26079
XEOF
fi
if [ '${EXTRA}' = 'parent' ]; then
cat > /root/extra_routes_${id}.txt <<'XEOF'
ROUTE 0 2 ${HOST} 26196
ROUTE 2 2 ${HOST} 26084
ROUTE 4 1 127.0.0.1 8800
XEOF
fi

for s in wvm5m_${id} wvm5s_${id} wvm5g_${id} wvm5x_${id}; do tmux kill-session -t \$s 2>/dev/null || true; done
pkill -x wavevm_gateway 2>/dev/null || true
pkill -x wavevm_node_master 2>/dev/null || true
pkill -x wavevm_node_slave 2>/dev/null || true
sleep 1
: > /tmp/wvm_master_${id}.log
: > /tmp/wvm_slave_${id}.log
: > /tmp/wvm_sidecar_${id}.log
: > /tmp/wvm_extra_${id}.log

tmux new-session -d -s wvm5g_${id} \"cd ${REMOTE_ROOT}; ./gateway_service/wavevm_gateway 8804 ${SIDE_UP_IP} ${SIDE_UP_PORT} /root/sidecar_routes_${id}.txt 8801 >>/tmp/wvm_sidecar_${id}.log 2>&1\"

if [ '${EXTRA}' != 'none' ]; then
  if [ '${EXTRA}' = 'parent' ]; then EX_PORT=8803; else EX_PORT=8802; fi
  tmux new-session -d -s wvm5x_${id} \"cd ${REMOTE_ROOT}; ./gateway_service/wavevm_gateway \$EX_PORT ${SIDE_UP_IP} ${SIDE_UP_PORT} /root/extra_routes_${id}.txt ${EXTRA_CTRL} >>/tmp/wvm_extra_${id}.log 2>&1\"
fi

sleep 1
tmux new-session -d -s wvm5m_${id} \"cd ${REMOTE_ROOT}; WVM_INSTANCE_ID=fractal_h2_${id} WVM_SHM_FILE=/wvm_master_h2_${id} ./master_core/wavevm_node_master 1024 8800 /root/swarm5_hier.conf ${id} 8801 8805 1 >>/tmp/wvm_master_${id}.log 2>&1\"
sleep 2
tmux new-session -d -s wvm5s_${id} \"cd ${REMOTE_ROOT}; WVM_SHM_FILE=/wvm_slave_h2_${id} ./slave_daemon/wavevm_node_slave 8805 1 1024 ${id} 8801 >>/tmp/wvm_slave_${id}.log 2>&1\"
"
done

sleep 10
echo "== snapshot =="
for i in "${!NODE_IDS[@]}"; do
  id="${NODE_IDS[$i]}"
  run_ssh "${PASSES[$i]}" "${PORTS[$i]}" \
    "echo [node ${id}]; tmux ls | egrep 'wvm5(m|s|g|x)_${id}' || true; \
     n=\$(grep -c 'New neighbor discovered' /tmp/wvm_master_${id}.log 2>/dev/null || echo 0); \
     c=\$(grep -c 'Severe Congestion' /tmp/wvm_master_${id}.log 2>/dev/null || echo 0); \
     b=\$(grep -ch 'bind failed\\|FATAL: Control plane bind failed' /tmp/wvm_sidecar_${id}.log /tmp/wvm_extra_${id}.log 2>/dev/null | awk '{s+=\$1} END{print s+0}'); \
     echo neighbors=\$n congestion=\$c bind_errs=\$b"
done
