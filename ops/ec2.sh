#!/usr/bin/env bash
# Start / stop the lab's EC2 GPU instance from this machine (AWS CLI, profile terraform).
#   bash ops/ec2.sh start    # IP check -> start -> wait for SSH -> print host -> auto-stop timer
#   bash ops/ec2.sh stop
#   bash ops/ec2.sh status   # state, host, and whether this machine's IP may connect
# Security-group changes stay with the user: when this machine's public IP is not
# allowed, the script prints the commands for them and does NOT start (no paying
# for an instance nobody can reach).
set -euo pipefail
export AWS_PROFILE="${EC2_AWS_PROFILE:-terraform}" AWS_DEFAULT_REGION="${EC2_REGION:-us-east-1}"
ID="${EC2_INSTANCE_ID:-i-0e3250dfa22b8e0ed}"
KEY="$(cd "$(dirname "$0")/.." && pwd)/key-to-hermes.pem"
AUTO_STOP_MIN="${AUTO_STOP_MIN:-180}"     # safety net if the work session dies mid-way
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8)

q() { aws ec2 describe-instances --instance-ids "$ID" --query "Reservations[0].Instances[0].$1" --output text; }

ip_check() {   # exit 0 when this machine's public IP is inside an allowed CIDR
  local me sg allowed
  me=$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')
  sg=$(q "SecurityGroups[0].GroupId")
  allowed=$(aws ec2 describe-security-groups --group-ids "$sg" \
              --query "SecurityGroups[0].IpPermissions[].IpRanges[].CidrIp" --output text)
  if python -c "import ipaddress, sys; ip = ipaddress.ip_address(sys.argv[1]); \
sys.exit(0 if any(ip in ipaddress.ip_network(c) for c in sys.argv[2:]) else 1)" "$me" $allowed; then
    echo "IP ok: $me is allowed by $sg"
    return 0
  fi
  cat >&2 <<EOF
IP CHANGED: this machine is $me; security group $sg allows: $allowed
Allow the new IP (run it yourself):
  aws ec2 authorize-security-group-ingress --profile $AWS_PROFILE --region $AWS_DEFAULT_REGION --group-id $sg --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=$me/32}]'
and drop the old one:
EOF
  for old in $allowed; do
    echo "  aws ec2 revoke-security-group-ingress --profile $AWS_PROFILE --region $AWS_DEFAULT_REGION --group-id $sg --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=$old}]'" >&2
  done
  return 1
}

cmd_start() {
  ip_check || exit 3
  case "$(q State.Name)" in
    running) ;;
    stopping) aws ec2 wait instance-stopped --instance-ids "$ID"; aws ec2 start-instances --instance-ids "$ID" >/dev/null ;;
    *) aws ec2 start-instances --instance-ids "$ID" >/dev/null ;;
  esac
  aws ec2 wait instance-running --instance-ids "$ID"
  local host
  host=$(q PublicDnsName)
  for _ in $(seq 1 30); do ssh "${SSH_OPTS[@]}" "ubuntu@$host" true 2>/dev/null && break; sleep 5; done
  # shutdown from inside stops (not terminates) only when the attribute says so
  if [ "$(aws ec2 describe-instance-attribute --instance-id "$ID" --attribute instanceInitiatedShutdownBehavior \
          --query InstanceInitiatedShutdownBehavior.Value --output text)" = stop ]; then
    ssh "${SSH_OPTS[@]}" "ubuntu@$host" "sudo shutdown -h +$AUTO_STOP_MIN" 2>/dev/null \
      && echo "auto-stop in $AUTO_STOP_MIN min (extend: sudo shutdown -h +N)"
  else
    echo "WARNING: shutdown behavior is not 'stop' — no auto-stop timer set" >&2
  fi
  echo "host: ubuntu@$host"
}

cmd_stop() {
  aws ec2 stop-instances --instance-ids "$ID" >/dev/null
  echo "stopping $ID"
}

cmd_status() {
  echo "state: $(q State.Name)   host: $(q PublicDnsName)"
  ip_check || true
}

case "${1:-status}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
