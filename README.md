# IDS + AI Agent Security System

Hệ thống phát hiện và ngăn chặn tấn công lai ghép: **Suricata IDS** (rule-based, <1ms) + **AI Agent** (Qwen2.5-14B, contextual analysis). Target thử nghiệm: **DVWA** (Damn Vulnerable Web Application).

```
Attacker → Nginx → WAF (OWASP CRS, chỉ ghi log) → DVWA · Suricata (detect) → AI Agent (decide) → iptables (block)
```

---

## Agent hoạt động thế nào

Agent đọc **hai nguồn**: alert của Suricata (`eve.json`) và web log của Nginx — nên nó thấy cả những request IDS
không báo. Trong benchmark, hai nguồn ghép theo `eid` (id mà bộ replay gắn vào mỗi request). Với traffic thật, dòng
nginx mang `request_id` và được ghép với alert của cùng request theo cổng nguồn + method + URI; IP lấy từ nginx (chỉ
tin `X-Forwarded-For` từ proxy nội bộ). Alert trùng (cùng nguồn, cùng rule trong 5 phút) chỉ được xét một lần.
Mỗi event đi qua một LangGraph `StateGraph`:

```
event ─▶ triage ─┬─ confidence 0.35–0.75 ─▶ investigate ─┐
                 └──────────── còn lại ──────────────────┴─▶ risk_gate ─▶ act
```

- **triage** — Qwen2.5-14B (Ollama, GPU) xét từng event một (`TRIAGE_BATCH=1`) và trả về `Decision` theo schema
  Pydantic ([agent/schemas.py](agent/schemas.py)): `action` (block / warn / log), loại tấn công, `confidence` = xác
  suất là tấn công, kỹ thuật MITRE ATT&CK, mức độ, ghi chú cho analyst, lý do.
- **investigate** — với ca mơ hồ: vòng ReAct tối đa 3 bước, chỉ gọi tool chỉ-đọc
  ([agent/tools/agent_tools.py](agent/tools/agent_tools.py)).
- **risk_gate** — `block` có confidence < 0.90, hoặc có lý do nhắc tới bằng chứng không có trong event, phải chờ
  người duyệt (`interrupt()`; duyệt trên dashboard khi `AUTO_APPROVE=false`).
- **act** — ghi quyết định, chặn IP bằng một `ipset` có thời hạn 1 giờ (kernel tự gỡ, kể cả khi agent khởi động lại).
  Chỉ [agent/actions.py](agent/actions.py) làm việc này, tool thì không. Lý do của model được đối chiếu với event
  (nhắc alert IDS khi không có alert, sai severity, nói "encoded" khi request không mã hóa); sai thì dashboard ghi
  "unverified".
- Nội dung request là dữ liệu của kẻ tấn công: được bọc trong `<<UNTRUSTED_DATA>>` và prompt cấm làm theo chỉ dẫn bên
  trong (chống prompt injection).
- Tùy chọn `MEMORY_ENABLED`: truy hồi 3 ca cũ giống nhất (embedding `nomic-embed-text`) làm ví dụ cho model.

---

## Kết quả thí nghiệm (2026-11-01)

Câu hỏi: agent có phát hiện tốt hơn IDS rule-based không, tốt hơn ở đâu, đánh đổi gì? Thiết kế:
[docs/EXPERIMENT_DESIGN.md](docs/EXPERIMENT_DESIGN.md); cách chạy lại: [benchmark/README.md](benchmark/README.md).

**Cách đo.** Tập test 147 request HTTP (76 tấn công / 71 lành) gửi tới DVWA, payload lấy từ nguồn công khai, chia
5 nhóm: tấn công rõ, evasion, recon (brute force, dò thư mục), request lành thường, và *fp_bait* (request lành nhưng có
từ khóa giống tấn công). Mỗi mode chạy 5 lần; chấm ở tầng quyết định (block/warn = phát hiện). Khoảng tin cậy 95% là
bootstrap ghép cặp theo request (B=2000). Số liệu gốc (CSV): [benchmark/results/test-final-v3/](benchmark/results/test-final-v3/);
code tạo ra chúng ở tag `exp-2026-11-01`. Các cải tiến sau đó (2026-11-02: web log cho traffic thật, gộp alert, kiểm
lý do, ipset) không đổi quyết định trên benchmark: chạy lại tập dev cho kết quả trùng lần trước.

| mode | cách quyết định | Precision | Recall | F1 | FPR | MTTB |
|---|---|---|---|---|---|---|
| `rule_based` | Suricata (ET Open + rule riêng), chặn khi severity ≤ 2 | 1.00 | 0.32 | 0.48 | 0.00 | 2.1 s |
| `waf` | OWASP CRS trên ModSecurity | 0.96 | 0.71 | 0.82 | 0.03 | 2.6 s |
| `agent_ids` | LLM, chỉ đọc alert Suricata (ablation) | 1.00 | 0.30 | 0.46 | 0.00 | 8.1 s |
| **`agent`** | LLM, đọc alert + web log | 0.85 | 0.96 | **0.90** [0.85, 0.94] | 0.18 [0.10, 0.27] | 14.7 s |

`naive` (chặn mọi alert) cho kết quả y hệt `rule_based` trên tập này.

| chênh lệch | Recall | FPR | F1 |
|---|---|---|---|
| agent − rule_based | +0.64 [+0.53, +0.75] | +0.18 [+0.10, +0.27] | **+0.42 [+0.30, +0.55]** |
| agent − waf | +0.25 [+0.16, +0.35] | +0.15 [+0.06, +0.25] | **+0.08 [+0.005, +0.17]** |

| nhóm (bắt được / tổng) | n | rule_based | waf | agent |
|---|---|---|---|---|
| tấn công rõ | 26 | 13 | 23 | 26 |
| evasion | 26 | 7 | 23 | 26 |
| recon | 24 | 4 | 8 | 21 |
| lành thường (báo nhầm) | 42 | 0 | 0 | 9 |
| fp_bait (báo nhầm) | 29 | 0 | 2 | 4 |

Đọc kết quả:
- **Agent bắt gần hết tấn công** (recall 0.96), kể cả evasion và recon, nhưng **báo nhầm nhiều hơn**: 13/71 request
  lành, so với 2 của WAF và 0 của IDS. Giả thuyết ban đầu "agent giảm báo nhầm" không đúng: trên tập này IDS vốn không
  báo nhầm.
- So với WAF, agent hơn F1 một chút (khoảng tin cậy vừa không chứa 0). Phần hơn nằm ở recon (21 so với 8): loại tấn
  công trải trên nhiều request, CRS không có rule cho nó.
- **Lợi thế đến từ nguồn dữ liệu, không từ việc LLM xét lại alert:** `agent_ids` (cùng LLM, chỉ đọc alert) ≈
  `rule_based`. Vòng investigate không được gọi lần nào trong lần đo này.
- 11/13 báo nhầm là `warn` (cảnh báo cho analyst), 2 là `block`; ~45/47 lệnh block là đúng.
- `confidence` khớp thực tế (ECE 0.041). Kỹ thuật MITRE đúng 82% trên các tấn công bắt được; phần lớn lỗi là dò thư
  mục bị gán T1083 thay vì T1595.
- 5 lần chạy cho kết quả y hệt nhau, nên độ bất định nằm ở mẫu request (khoảng tin cậy), không ở các lần chạy.

**Thử nghiệm phụ** (2026-10-27, bản prompt trước đó — chỉ khác ở định nghĩa `confidence`):
- *Prompt injection* (12 kỹ thuật × 2 lần): tỉ lệ vượt qua 12% khi không phòng thủ → 0% khi có quy tắc trong prompt
  (có hoặc không bọc dữ liệu); mẫu nhỏ nên khoảng tin cậy rộng.
- *Experience memory* (3 epoch): bớt ròng 3 báo nhầm so với khi tắt (14 so với 17), không có đường học rõ.
- *ET Open nguyên bản* (không tinh chỉnh rule): kết luận không đổi.

---

## Giới hạn

- **Báo nhầm trên trang có lỗ hổng với input bình thường** (`fi/?page=file1.php`, đăng nhập bằng user mặc định của
  DVWA) và với từ khóa (`union`). Bản sửa prompt chỉnh trên tập dev không áp được sang tập test.
- **Lý do không luôn bám bằng chứng:** 3 lần báo nhầm ghi "IDS severity 1/2" trong khi không có alert nào — cụm này
  chép từ ví dụ trong prompt; vài lý do ghi "encoded" cho tên trang thường. Từ 2026-11-02 những lý do kiểu này được
  đánh dấu "unverified" (trên tập dev: 2/54 quyết định). Kiểm bằng luật đơn giản nên không bắt được mọi kiểu bịa.
- **Chậm và tốn GPU:** ~4 s LLM cho mỗi request trên T4 (~15 request/phút); MTTB 14.7 s so với 2–3 s của IDS/WAF.
  Agent xét mọi request nên không theo kịp traffic thật nếu không lọc bớt trước.
- **Vẫn có thể nghẽn:** một đợt apt của chính máy chủ (211 alert) từng làm trễ phát hiện hơn 10 phút. Từ 2026-11-02
  alert trùng (cùng nguồn, cùng rule trong 5 phút) chỉ xét một lần — 8 request tấn công giống nhau từ ngoài vào chỉ
  tốn 1 lần gọi LLM. Nhưng nhiều alert hay request *khác nhau* vẫn xếp hàng, mỗi cái ~4 s.
- **Web log của traffic thật mới thử ở quy mô nhỏ:** từ 2026-11-02 agent đọc cả dòng nginx không có `eid` (id theo
  `request_id`, ghép với alert theo cổng nguồn). Đã thử với request từ ngoài vào EC2: ghép đúng, chặn đúng IP. Nhưng
  mọi con số ở trên vẫn đo trên benchmark, và agent xét mọi request nên chỉ chịu được ~15 request/phút.
- **IP trong alert có thể bị giả:** Suricata lấy IP từ `X-Forwarded-For` của mọi client (bộ replay cần điều này). Alert
  ghép được với dòng nginx dùng IP của nginx; alert không ghép được (không phải HTTP, hoặc dòng nginx đến trễ quá 2
  phút) vẫn mang IP do client tự khai, nên agent có thể chặn nhầm IP.
- **Phạm vi đo hẹp:** 147 request, một ứng dụng (DVWA), ~52% là tấn công. Bộ replay không đăng nhập DVWA nên trang lỗ
  hổng chuyển hướng về trang login: payload không thực sự chạy, chỉ đo việc phát hiện trên request (rule IDS dựa vào
  phản hồi không có dịp bắn). Với traffic thật, tấn công hiếm hơn nhiều nên precision sẽ thấp hơn. Tập test đã được
  dùng hai lần (prompt cũ rồi bản thêm định nghĩa `confidence`).
- Kết quả experience memory ở trên là của bản có lỗi (`record_feedback` xóa bài học khi agent làm đúng một lần). Lỗi đã
  sửa ngày 2026-11-02 nhưng chưa đo lại.

---

## Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| AWS EC2 | g4dn.xlarge (T4 16GB VRAM, 4 vCPU, 16GB RAM) |
| AMI | Ubuntu 24.04 LTS |
| Storage | 50GB GP3 |
| Docker | ≥ 24.0 |
| Docker Compose | ≥ v2.20 |
| NVIDIA Driver | ≥ 525 (có sẵn trong Deep Learning AMI) |

---

## Bước 1 — Tạo EC2 Instance

### 1.1 Chọn AMI và instance type

Vào AWS Console → EC2 → Launch Instance:
- **AMI**: `Ubuntu Server 24.04 LTS` (hoặc `Deep Learning Base OSS Nvidia Driver GPU AMI` để có NVIDIA driver sẵn)
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
# Docker từ repo chính thức của Docker (máy lab chạy bản này: docker-ce 29 + compose v5)
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
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
docker run --rm --gpus all nvidia/cuda:12.0.0-base-ubuntu22.04 nvidia-smi
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
# Chạy suricata-update để download ET Open rules. disable.conf tắt các rule
# Modbus/DNP3 (thiếu chúng thì `suricata -T` của suricata-update fail) và rule nhiễu
# 2221036 — xem ids/rules/disable.conf
docker run --rm \
  -v $(pwd)/ids/rules:/etc/suricata/rules \
  jasonish/suricata:latest \
  suricata-update --no-reload --disable-conf /etc/suricata/rules/disable.conf \
    --output /etc/suricata/rules
# Khi stack đã chạy: `bash ids/update_rules.sh` (cài + kiểm + restart Suricata);
# `bash ids/update_rules.sh untuned` cho lần chạy phụ lục trên ET Open nguyên bản.
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
waf         running
dvwa        running
mysql       running (healthy)
suricata    running
ollama      running (healthy) 0.0.0.0:11434->11434/tcp
agent       running
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
# Dấu cách viết %20, không dùng '+': pcre của rule 9000001 cần khoảng trắng thật sau khi giải mã URL
curl "http://<EC2_IP>/vulnerabilities/sqli/?id=1'%20OR%201=1--&Submit=Submit" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### XSS Reflected
```bash
curl "http://<EC2_IP>/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### Command Injection
```bash
curl "http://<EC2_IP>/vulnerabilities/exec/" \
  --data "ip=127.0.0.1;id&Submit=Submit" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### LFI / Path Traversal
```bash
curl "http://<EC2_IP>/vulnerabilities/fi/?page=../../../../../../etc/passwd" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### Brute Force (10 requests nhanh)
```bash
for i in {1..12}; do
  curl -s -o /dev/null "http://<EC2_IP>/login.php" \
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
├── ROADMAP.md                    # Kế hoạch + trạng thái Giai đoạn 2
├── webserver/
│   └── nginx/nginx.conf          # Reverse proxy + JSON logging
├── ids/
│   ├── suricata.yaml             # Cấu hình Suricata
│   ├── update_rules.sh           # Cài ET Open (bản tinh chỉnh / nguyên bản) + kiểm
│   └── rules/
│       ├── custom.rules          # Rules tùy chỉnh cho DVWA
│       ├── disable*.conf         # Rule ET Open bị tắt (bản tinh chỉnh / nguyên bản)
│       └── suricata.rules        # ET Open rules (download ở Bước 4.1)
├── agent/
│   ├── Dockerfile
│   ├── main.py                   # Agent loop chính (poll log → graph / rule modes)
│   ├── graph.py                  # LangGraph: triage → investigate → risk_gate → act
│   ├── schemas.py                # Pydantic Decision (structured output)
│   ├── actions.py                # Ghi quyết định + block IP
│   ├── gate.py                   # Phân tầng rủi ro cho HITL
│   ├── approvals.py              # Hàng chờ duyệt block (HITL)
│   ├── approve.py                # Duyệt block từ dòng lệnh
│   ├── demo_hitl.py              # Demo người duyệt block
│   ├── requirements.txt
│   ├── tools/
│   │   ├── agent_tools.py        # Tool chỉ-đọc cho vòng investigate
│   │   ├── alert_reader.py       # Đọc EVE JSON / nginx log theo offset
│   │   ├── firewall.py           # Wrapper iptables
│   │   ├── memory.py             # Experience memory (bài học từ feedback)
│   │   ├── prompt_guard.py       # Bọc dữ liệu untrusted (<<UNTRUSTED_DATA>>)
│   │   └── notifier.py           # Ghi log + webhook
│   └── prompts/
│       └── system.md             # System prompt LLM
├── dashboard/
│   ├── Dockerfile
│   ├── app.py                    # Flask API
│   └── templates/
│       └── index.html            # UI dashboard
├── benchmark/                    # Harness A/B: corpus, replay, chấm điểm, CI (xem benchmark/README.md)
│   └── results/test-final-v3/    # Số liệu gốc của lần đo 2026-11-01
├── docs/                         # Thiết kế thí nghiệm, corpus v2
├── notes/                        # Review + checklist sửa lỗi
├── ops/ec2.sh                    # Bật/tắt EC2 của lab
└── tests/                        # pytest, chạy offline
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
- OLLAMA_MODEL=qwen2.5:7b   # ~5GB RAM
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
