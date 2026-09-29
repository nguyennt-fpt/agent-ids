# IDS + AI Agent Security System

Hệ thống phát hiện và ngăn chặn tấn công lai ghép: **Suricata IDS** (rule-based, <1ms) + **AI Agent** (Qwen2.5-14B, contextual analysis). Target thử nghiệm: **DVWA** (Damn Vulnerable Web Application).

```
Attacker → Nginx → DVWA → Suricata (detect) → AI Agent (decide) → iptables (block)
```

---

## Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| AWS EC2 | g4dn.xlarge (T4 16GB VRAM, 4 vCPU, 16GB RAM) |
| AMI | Ubuntu 22.04 LTS |
| Storage | 50GB GP3 |
| Docker | ≥ 24.0 |
| Docker Compose | ≥ v2.20 |
| NVIDIA Driver | ≥ 525 (có sẵn trong Deep Learning AMI) |

---

## Bước 1 — Tạo EC2 Instance

### 1.1 Chọn AMI và instance type

Vào AWS Console → EC2 → Launch Instance:
- **AMI**: `Ubuntu Server 22.04 LTS` (hoặc `Deep Learning Base OSS Nvidia Driver GPU AMI` để có NVIDIA driver sẵn)
- **Instance type**: `g4dn.xlarge`
- **Storage**: 50 GB GP3

### 1.2 Security Group

```
Inbound rules:
  Type: SSH      Port: 22    Source: <YOUR_IP>/32
  Type: HTTP     Port: 80    Source: <YOUR_IP>/32
  Type: Custom   Port: 5000  Source: <YOUR_IP>/32

Outbound: All traffic (để pull Docker images và Ollama model)
```

### 1.3 Key pair
Tạo hoặc chọn key pair `.pem` để SSH.

---

## Bước 2 — Setup môi trường trên EC2

SSH vào instance:
```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

### 2.1 Cài Docker và NVIDIA Container Toolkit

```bash
# Docker
sudo apt-get update -y
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# NVIDIA driver (nếu dùng Ubuntu AMI thuần, bỏ qua nếu dùng Deep Learning AMI)
sudo apt-get install -y ubuntu-drivers-common
sudo ubuntu-drivers autoinstall
sudo reboot
# SSH lại sau khi reboot

# NVIDIA Container Toolkit
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
  sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update -y
sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# Kiểm tra GPU
docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu22.04 nvidia-smi
```

---

## Bước 3 — Clone và cấu hình project

```bash
git clone <repo_url> agent-ids
cd agent-ids
```

Hoặc copy toàn bộ thư mục lên EC2 bằng `scp`:
```bash
scp -i your-key.pem -r ./agent-ids ubuntu@<EC2_IP>:~/
```

---

## Bước 4 — Khởi động hệ thống

### 4.1 Pull Suricata rules (một lần)

```bash
# Chạy suricata-update để download ET Open rules
docker run --rm \
  -v $(pwd)/ids/rules:/etc/suricata/rules \
  jasonish/suricata:latest \
  suricata-update --no-reload --output /etc/suricata/rules
```

### 4.2 Start tất cả services

```bash
docker compose up -d
```

Lần đầu sẽ mất 5-10 phút để pull images.

### 4.3 Pull Ollama model (quan trọng — chỉ làm 1 lần)

```bash
docker exec ollama ollama pull qwen2.5:14b
```

> Qwen2.5-14B Q4_K_M ~9GB — quá trình download mất 10-20 phút tùy băng thông.

### 4.4 Kiểm tra tất cả services đang chạy

```bash
docker compose ps
```

Kết quả mong đợi:
```
NAME        STATUS          PORTS
nginx       running         0.0.0.0:80->80/tcp
dvwa        running
mysql       running (healthy)
suricata    running
ollama      running (healthy) 0.0.0.0:11434->11434/tcp
agent       running         0.0.0.0:8000->8000/tcp
dashboard   running         0.0.0.0:5000->5000/tcp
```

---

## Bước 5 — Thiết lập DVWA

1. Mở trình duyệt: `http://<EC2_IP>/setup.php`
2. Click **"Create / Reset Database"**
3. Đăng nhập: `admin` / `password`
4. Vào **DVWA Security** → chọn **"Low"** → Submit

---

## Bước 6 — Test tấn công

Mở terminal mới, thay `<EC2_IP>` và `<PHPSESSID>` (lấy từ browser DevTools → cookies):

### SQL Injection
```bash
curl "http://<EC2_IP>/dvwa/vulnerabilities/sqli/?id=1'+OR+1=1--&Submit=Submit" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### XSS Reflected
```bash
curl "http://<EC2_IP>/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### Command Injection
```bash
curl "http://<EC2_IP>/dvwa/vulnerabilities/exec/" \
  --data "ip=127.0.0.1;id&Submit=Submit" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### LFI / Path Traversal
```bash
curl "http://<EC2_IP>/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### Brute Force (10 requests nhanh)
```bash
for i in {1..12}; do
  curl -s -o /dev/null "http://<EC2_IP>/dvwa/login.php" \
    --data "username=admin&password=wrong$i&Login=Login" \
    -b "security=low; PHPSESSID=<PHPSESSID>"
done
```

---

## Bước 7 — Xem kết quả

### Dashboard
Mở trình duyệt: `http://<EC2_IP>:5000`

### Agent log (real-time decisions)
```bash
docker logs -f agent
```

### Suricata alerts
```bash
docker exec suricata tail -f /var/log/suricata/fast.log
```

### IPs đang bị block
```bash
docker exec agent python -c \
  "from tools.firewall import get_blocked_ips; import json; print(json.dumps(get_blocked_ips(), indent=2))"
```

### Kiểm tra iptables trực tiếp
```bash
sudo iptables -L DOCKER-USER -n --line-numbers
```

---

## Cấu trúc file

```
agent-ids/
├── docker-compose.yml
├── CLAUDE.md                     # Hướng dẫn cho Claude Code
├── README.md                     # File này
├── webserver/
│   └── nginx/nginx.conf          # Reverse proxy + JSON logging
├── ids/
│   ├── suricata.yaml             # Cấu hình Suricata
│   └── rules/
│       ├── custom.rules          # Rules tùy chỉnh cho DVWA
│       └── suricata.rules        # ET Open rules (download ở Bước 4.1)
├── agent/
│   ├── Dockerfile
│   ├── main.py                   # Agent loop chính (poll log → graph / rule modes)
│   ├── graph.py                  # LangGraph: triage → investigate → risk_gate → act
│   ├── schemas.py                # Pydantic Decision (structured output)
│   ├── actions.py                # Ghi quyết định + block IP
│   ├── gate.py                   # Phân tầng rủi ro cho HITL
│   ├── demo_hitl.py              # Demo người duyệt block
│   ├── requirements.txt
│   ├── tools/
│   │   ├── agent_tools.py        # Tool chỉ-đọc cho vòng investigate
│   │   ├── alert_reader.py       # Đọc EVE JSON / nginx log theo offset
│   │   ├── firewall.py           # Wrapper iptables
│   │   ├── ids_manager.py        # Quản lý rule Suricata
│   │   └── notifier.py           # Ghi log + webhook
│   └── prompts/
│       └── system.md             # System prompt LLM
└── dashboard/
    ├── Dockerfile
    ├── app.py                    # Flask API
    └── templates/
        └── index.html            # UI dashboard
```

---

## Tuning và mở rộng

### Thay đổi ngưỡng block confidence
Sửa trong [agent/prompts/system.md](agent/prompts/system.md):
```
### Block immediately (confidence ≥ 0.90)   ← thay số này
```

### Thêm detection rule mới
Thêm vào [ids/rules/custom.rules](ids/rules/custom.rules), SID phải > 9000000:
```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
  (msg:"Custom - My new rule"; flow:established,to_server; \
  http.uri; content:"malicious_pattern"; \
  classtype:web-application-attack; sid:9000100; rev:1;)
```

Reload Suricata:
```bash
docker exec suricata suricatasc -c reload-rules
```

### Đổi sang model nhỏ hơn (máy yếu hơn)
Trong `docker-compose.yml`, sửa biến môi trường agent:
```yaml
OLLAMA_MODEL: qwen2.5:7b   # ~5GB RAM
```
Và pull model mới:
```bash
docker exec ollama ollama pull qwen2.5:7b
```

### Bật webhook alert (Slack/Teams)
Trong `docker-compose.yml`, thêm vào `agent` service:
```yaml
environment:
  - WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

---

## Dừng hệ thống

```bash
# Dừng tất cả (giữ data)
docker compose down

# Dừng và xóa toàn bộ data (reset sạch)
docker compose down -v
```

---

## Lưu ý bảo mật

> Hệ thống này chứa ứng dụng **có lỗ hổng cố ý** (DVWA). Chỉ triển khai trong môi trường lab/test cô lập. **Không expose port 80 ra Internet công cộng.** Security Group phải giới hạn theo IP của bạn.
