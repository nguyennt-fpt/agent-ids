# IDS + AI Agent Security System

A hybrid attack detection and response system: **Suricata IDS** (rule-based, <1ms) + **AI Agent** (Qwen2.5-14B, contextual analysis). Test target: **DVWA** (Damn Vulnerable Web Application).

```
Attacker → Nginx → WAF (OWASP CRS, logging only) → DVWA · Suricata (detect) → AI Agent (decide) → iptables (block)
```

---

## How the agent works

The agent reads **two sources**: Suricata alerts (`eve.json`) and the Nginx web log — so it also sees requests the IDS
does not alert on. In the benchmark the two sources are joined on `eid` (an id the replay tool puts on every request).
For real traffic, each nginx line carries a `request_id` and is joined with the alert for the same request by source
port + method + URI; the IP comes from nginx (`X-Forwarded-For` is trusted only from the internal proxy). Duplicate
alerts (same source, same rule within 5 minutes) are judged once. Each event goes through a LangGraph `StateGraph`:

```
event ─▶ triage ─┬─ confidence 0.35–0.75 ─▶ investigate ─┐
                 └──────────── otherwise ────────────────┴─▶ risk_gate ─▶ act
```

- **triage** — Qwen2.5-14B (Ollama, GPU) judges one event at a time (`TRIAGE_BATCH=1`) and returns a `Decision`
  following a Pydantic schema ([agent/schemas.py](agent/schemas.py)): `action` (block / warn / log), attack type,
  `confidence` = probability that it is an attack, MITRE ATT&CK technique, severity, analyst note, reason.
- **investigate** — for ambiguous cases: a ReAct loop of at most 3 steps that can only call read-only tools
  ([agent/tools/agent_tools.py](agent/tools/agent_tools.py)).
- **risk_gate** — a `block` with confidence < 0.90, or whose reason cites evidence that is not in the event, waits for
  a human (`interrupt()`; approved on the dashboard when `AUTO_APPROVE=false`).
- **act** — records the decision and blocks the IP with an `ipset` entry that expires after 1 hour (the kernel removes
  it, even if the agent restarts). Only [agent/actions.py](agent/actions.py) does this, never a tool. The model's reason
  is checked against the event (citing an IDS alert when there is none, wrong severity, saying "encoded" when the
  request is not encoded); if it does not match, the dashboard marks it "unverified".
- Request content is attacker-controlled data: it is wrapped in `<<UNTRUSTED_DATA>>` and the prompt forbids following
  instructions inside it (prompt-injection defense).
- Optional `MEMORY_ENABLED`: retrieves the 3 most similar past cases (`nomic-embed-text` embeddings) as examples for
  the model.

---

## Experiment results (2026-11-03)

Question: does the agent detect better than a rule-based IDS, where, and at what cost? Design:
[docs/EXPERIMENT_DESIGN.md](docs/EXPERIMENT_DESIGN.md); how to reproduce: [benchmark/README.md](benchmark/README.md).

**Method.** A test set of 147 HTTP requests (76 attacks / 71 benign) sent to DVWA, payloads taken from public sources,
in 5 groups: clear attacks, evasion, recon (brute force, directory scanning), normal benign requests, and *fp_bait*
(benign requests containing attack-like keywords). Plus a **held_out** set: 61 new attacks never replayed while
tuning. Each mode runs 5 times; scoring is at the decision layer (block/warn = detected). 95% confidence intervals are
a request-paired bootstrap (B=2000). Raw numbers (CSV): [benchmark/results/](benchmark/results/) (`test-final-v4/`,
`held-out-v4/`, …); code at tag `exp-2026-11-03`. Prompt v4 was chosen on the dev set against a pre-registered
criterion (fewer false positives than v3, no new misses), before any test or held_out run.

| mode | how it decides | Precision | Recall | F1 | FPR | MTTB |
|---|---|---|---|---|---|---|
| `rule_based` | Suricata (ET Open + custom rules), block when severity ≤ 2 | 1.00 | 0.32 | 0.48 | 0.00 | 2.1 s |
| `waf` | OWASP CRS on ModSecurity | 0.96 | 0.71 | 0.82 | 0.03 | 2.6 s |
| `agent_ids` | LLM, reads Suricata alerts only (ablation) | 1.00 | 0.30 | 0.46 | 0.00 | 8.3 s |
| **`agent`** | LLM, reads alerts + web log | 0.91 | 0.95 | **0.93** [0.88, 0.96] | 0.10 [0.04, 0.18] | 14.7 s |
| *`agent` v3 (2026-11-01)* | | *0.85* | *0.96* | *0.90 [0.85, 0.94]* | *0.18 [0.10, 0.27]* | *14.7 s* |

`naive` (block every alert) gives exactly the same result as `rule_based` on this set.

| difference | Recall | FPR | F1 |
|---|---|---|---|
| agent − rule_based | +0.63 [+0.52, +0.74] | +0.10 [+0.04, +0.18] | **+0.45 [+0.33, +0.58]** |
| agent − waf | +0.24 [+0.15, +0.34] | +0.08 [+0.00, +0.16] | **+0.11 [+0.04, +0.19]** |

| group (caught / total, mean of 5 runs) | n | rule_based | waf | agent | agent v3 |
|---|---|---|---|---|---|
| clear attack | 26 | 13 | 23 | 26 | 26 |
| evasion | 26 | 7 | 23 | 26 | 26 |
| recon | 24 | 4 | 8 | 20.2 | 21 |
| normal benign (false positives) | 42 | 0 | 0 | 5.2 | 9 |
| fp_bait (false positives) | 29 | 0 | 2 | 2.2 | 4 |

**Held-out** (61 new attacks; attacks only, so only recall is meaningful):

| | rule_based | waf | agent_ids | agent v4 | agent v3 |
|---|---|---|---|---|---|
| Recall | 0.57 (35) | 0.93 (57) | 0.57 (35) | **1.00 (61)** | **1.00 (61)** |

The WAF missed 3 RFI and 1 command injection; the IDS missed all 12 command injections.

Reading the results:
- **The agent catches almost every attack** (recall 0.95 on test, 61/61 on held_out), including evasion and recon,
  but **still has more false positives**: ~7/71 benign requests, versus 2 for the WAF and 0 for the IDS. The initial
  hypothesis "the agent reduces false positives" does not hold: on this set the IDS has no false positives to begin
  with.
- **v4 nearly halves the false positives** (FPR 0.18 → 0.10). It fixes all 6 `fi/?page=<page name>` cases that the
  earlier fix did not carry over to test, plus one case containing the word "union". In exchange: 1 new false positive
  (`login.php?username=admin`) and 1 more missed directory-scan request. The two versions' confidence intervals still
  overlap, so the reduction is real on the specific cases but the sample is too small to claim it firmly.
- The remaining false positives are mostly logins with DVWA's default accounts on the brute-force page (5 cases).
- Against the WAF, the agent's F1 lead is clearer than with v3 (the confidence interval excludes 0). The lead comes
  from recon (20 vs 8): an attack spread over many requests, which CRS has no rules for.
- **The advantage comes from the data source, not from the LLM re-judging alerts:** `agent_ids` (same LLM, alerts
  only) ≈ `rule_based` on both test and held_out. The investigate loop was never invoked.
- `confidence` matches reality (ECE 0.04). The MITRE technique is correct for 85% of the caught attacks.
- Unlike v3, the 5 runs are no longer identical (3 distinct outcomes, differing by 1–2 requests); held_out runs are
  identical.
- **Held_out does not separate v3 from v4:** both catch all 61/61.

**Side experiments** (2026-11-03, v4):
- *Prompt injection* (25 techniques in 5 families × 2 repeats, 4 conditions toggling the defenses): **0% bypass in all
  4 conditions**, even with every defense off. The old run (2026-10-27, 12 techniques) had 12% bypass without defenses;
  the two techniques that got through then (`comment_injection`, `instruction_override`) are now blocked. Since
  removing the defenses lets nothing through either, this measurement can no longer separate the effect of each
  defense layer.
- *Experience memory* (3 epochs, re-measured after the `record_feedback` fix): **no gain**. Memory on: recall
  0.95 → 0.92, FPR stays 0.11; memory off: recall stays 0.95, FPR 0.11 → 0.13. The differences are 1–2 requests,
  within run-to-run noise.
- *Untuned ET Open* (2026-10-27, no rule tuning): the conclusions do not change.

---

## Limitations

- **False positives on vulnerable pages with normal input:** v4 no longer flags `fi/?page=file1.php`, but it still
  flags logins with DVWA's default users on the brute-force page and a few requests with keywords
  (`union-station-15`).
- **Reasons do not always follow the evidence:** 3 false positives said "IDS severity 1/2" when there was no alert —
  a phrase copied from an example in the prompt; some reasons said "encoded" for plain page names. Since 2026-11-02
  such reasons are marked "unverified" (on the dev set: 2/54 decisions). The check uses simple rules, so it does not
  catch every kind of fabrication.
- **Slow and GPU-hungry:** ~4 s of LLM time per request on a T4 (~15 requests/minute); MTTB 14.7 s versus 2–3 s for
  the IDS/WAF. The agent judges every request, so it cannot keep up with real traffic without pre-filtering.
- **Can still back up:** an apt run on the host itself (211 alerts) once delayed detection by more than 10 minutes.
  Since 2026-11-02, duplicate alerts (same source, same rule within 5 minutes) are judged once — 8 identical attack
  requests from outside cost a single LLM call. But many *different* alerts or requests still queue, ~4 s each.
- **Real-traffic web log only tried at small scale:** since 2026-11-02 the agent also reads nginx lines without an
  `eid` (keyed by `request_id`, joined with alerts by source port). Tried with requests from outside to the EC2 host:
  joined correctly, blocked the right IP. But every number above is still measured on the benchmark, and since the
  agent judges every request it only handles ~15 requests/minute.
- **IPs in alerts can be spoofed:** Suricata takes the IP from `X-Forwarded-For` for every client (the replay tool
  needs this). Alerts joined with an nginx line use nginx's IP; alerts that cannot be joined (not HTTP, or the nginx
  line arrives more than 2 minutes late) still carry the client-supplied IP, so the agent may block the wrong IP.
- **Narrow scope:** 147 requests, one application (DVWA), ~52% attacks. The replay tool does not log in to DVWA, so the
  vulnerable pages redirect to the login page: payloads never actually execute, only detection on the request is
  measured (IDS rules that depend on the response never get a chance to fire). With real traffic, attacks are far
  rarer, so precision will be lower. The test set has been used three times (2026-10-27, 2026-11-01, 2026-11-03); v4
  was tuned on dev, but having seen test results before may still make the numbers slightly optimistic. Held_out is
  cleaner but contains only attacks (false positives cannot be measured) and is too easy: both v3 and v4 reach 61/61.
- **The prompt-injection set is not strong enough:** 0% bypass even with the defenses off, so it does not show which
  defense layer helps. Harder samples are needed (e.g. attacks that adapt to the agent's responses).
- **Throughput not measured:** the benchmark measures decision quality at 1 request / 6 s, not how much traffic the
  agent can handle.

---

## System requirements

| Component | Requirement |
|---|---|
| AWS EC2 | g4dn.xlarge (T4 16GB VRAM, 4 vCPU, 16GB RAM) |
| AMI | Ubuntu 24.04 LTS |
| Storage | 50GB GP3 |
| Docker | ≥ 24.0 |
| Docker Compose | ≥ v2.20 |
| NVIDIA Driver | ≥ 525 (preinstalled on the Deep Learning AMI) |

---

## Step 1 — Create the EC2 instance

### 1.1 Choose the AMI and instance type

AWS Console → EC2 → Launch Instance:
- **AMI**: `Ubuntu Server 24.04 LTS` (or `Deep Learning Base OSS Nvidia Driver GPU AMI` to get the NVIDIA driver
  preinstalled)
- **Instance type**: `g4dn.xlarge`
- **Storage**: 50 GB GP3

### 1.2 Security Group

```
Inbound rules:
  Type: SSH      Port: 22    Source: <YOUR_IP>/32
  Type: HTTP     Port: 80    Source: <YOUR_IP>/32
  Type: Custom   Port: 5000  Source: <YOUR_IP>/32

Outbound: All traffic (to pull Docker images and the Ollama model)
```

### 1.3 Key pair
Create or choose a `.pem` key pair for SSH.

---

## Step 2 — Set up the environment on EC2

SSH into the instance:
```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

### 2.1 Install Docker and the NVIDIA Container Toolkit

```bash
# Docker from Docker's official repo (the lab host runs this: docker-ce 29 + compose v5)
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

# NVIDIA driver (on a plain Ubuntu AMI; skip on the Deep Learning AMI)
sudo apt-get install -y ubuntu-drivers-common
sudo ubuntu-drivers autoinstall
sudo reboot
# SSH back in after the reboot

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

# Check the GPU
docker run --rm --gpus all nvidia/cuda:12.0.0-base-ubuntu22.04 nvidia-smi
```

---

## Step 3 — Clone and configure the project

```bash
git clone https://github.com/nguyennt-fpt/agent-ids.git agent-ids
cd agent-ids
```

Or copy the whole folder to EC2 with `scp`:
```bash
scp -i your-key.pem -r ./agent-ids ubuntu@<EC2_IP>:~/
```

---

## Step 4 — Start the system

### 4.1 Pull Suricata rules (once)

```bash
# Run suricata-update to download the ET Open rules. disable.conf turns off the
# Modbus/DNP3 rules (without them suricata-update's `suricata -T` fails) and the noisy
# rule 2221036 — see ids/rules/disable.conf
docker run --rm \
  -v $(pwd)/ids/rules:/etc/suricata/rules \
  jasonish/suricata:latest \
  suricata-update --no-reload --disable-conf /etc/suricata/rules/disable.conf \
    --output /etc/suricata/rules
# Once the stack is running: `bash ids/update_rules.sh` (install + verify + restart Suricata);
# `bash ids/update_rules.sh untuned` for the appendix run on untuned ET Open.
```

### 4.2 Start all services

```bash
docker compose up -d
```

The first start takes 5–10 minutes to pull images.

### 4.3 Pull the Ollama model (important — once only)

```bash
docker exec ollama ollama pull qwen2.5:14b
```

> Qwen2.5-14B Q4_K_M is ~9GB — the download takes 10–20 minutes depending on bandwidth.

### 4.4 Check that every service is running

```bash
docker compose ps
```

Expected output:
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

## Step 5 — Set up DVWA

1. Open in a browser: `http://<EC2_IP>/setup.php`
2. Click **"Create / Reset Database"**
3. Log in: `admin` / `password`
4. Go to **DVWA Security** → choose **"Low"** → Submit

---

## Step 6 — Test attacks

In a new terminal, replace `<EC2_IP>` and `<PHPSESSID>` (from the browser's DevTools → cookies):

### SQL Injection
```bash
# Write spaces as %20, not '+': rule 9000001's pcre needs real whitespace after URL decoding
curl "http://<EC2_IP>/vulnerabilities/sqli/?id=1'%20OR%201=1--&Submit=Submit" \
  -b "security=low; PHPSESSID=<PHPSESSID>"
```

### Reflected XSS
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

### Brute Force (a quick burst of requests)
```bash
for i in {1..12}; do
  curl -s -o /dev/null "http://<EC2_IP>/login.php" \
    --data "username=admin&password=wrong$i&Login=Login" \
    -b "security=low; PHPSESSID=<PHPSESSID>"
done
```

---

## Step 7 — View the results

### Dashboard
Open in a browser: `http://<EC2_IP>:5000`

### Agent log (real-time decisions)
```bash
docker logs -f agent
```

### Suricata alerts
```bash
docker exec suricata tail -f /var/log/suricata/fast.log
```

### Currently blocked IPs
```bash
docker exec agent python -c \
  "from tools.firewall import get_blocked_ips; import json; print(json.dumps(get_blocked_ips(), indent=2))"
```

### Check iptables directly
```bash
sudo iptables -L DOCKER-USER -n --line-numbers
```

---

## File structure

```
agent-ids/
├── docker-compose.yml
├── README.md                     # This file
├── webserver/
│   └── nginx/nginx.conf          # Reverse proxy + JSON logging
├── ids/
│   ├── suricata.yaml             # Suricata config
│   ├── update_rules.sh           # Install ET Open (tuned / untuned) + verify
│   └── rules/
│       ├── custom.rules          # Custom rules for DVWA
│       ├── disable*.conf         # ET Open rules turned off (tuned / untuned)
│       └── suricata.rules        # ET Open rules (downloaded in Step 4.1)
├── agent/
│   ├── Dockerfile
│   ├── main.py                   # Main agent loop (poll logs → graph / rule modes)
│   ├── graph.py                  # LangGraph: triage → investigate → risk_gate → act
│   ├── schemas.py                # Pydantic Decision (structured output)
│   ├── actions.py                # Record decisions + block IPs
│   ├── gate.py                   # Risk tiering for HITL
│   ├── approvals.py              # Block approval queue (HITL)
│   ├── approve.py                # Approve blocks from the command line
│   ├── demo_hitl.py              # Human-approval demo
│   ├── requirements.txt
│   ├── tools/
│   │   ├── agent_tools.py        # Read-only tools for the investigate loop
│   │   ├── alert_reader.py       # Read EVE JSON / nginx log by offset
│   │   ├── firewall.py           # ipset + one DOCKER-USER rule
│   │   ├── memory.py             # Experience memory (lessons from feedback)
│   │   ├── prompt_guard.py       # Untrusted-data fencing (<<UNTRUSTED_DATA>>)
│   │   └── notifier.py           # Event log + webhook
│   └── prompts/
│       └── system.md             # LLM system prompt
├── dashboard/
│   ├── Dockerfile
│   ├── app.py                    # Flask API
│   └── templates/
│       └── index.html            # Dashboard UI
├── benchmark/                    # A/B harness: corpus, replay, scoring, CI (see benchmark/README.md)
│   └── results/                  # Raw numbers: test-final-v4 (main, 2026-11-03), held-out, g4, learning curve, v3
├── docs/                         # Experiment design
├── ops/ec2.sh                    # Start/stop the lab EC2
└── tests/                        # pytest, runs offline
```

---

## Tuning and extending

### Change the block confidence threshold
Edit [agent/prompts/system.md](agent/prompts/system.md):
```
### Block immediately (confidence ≥ 0.90)   ← change this number
```

### Add a new detection rule
Add it to [ids/rules/custom.rules](ids/rules/custom.rules); the SID must be > 9000000:
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

### Switch to a smaller model (weaker machine)
In `docker-compose.yml`, change the agent's environment variable:
```yaml
- OLLAMA_MODEL=qwen2.5:7b   # ~5GB RAM
```
And pull the new model:
```bash
docker exec ollama ollama pull qwen2.5:7b
```

### Enable webhook alerts (Slack/Teams)
In `docker-compose.yml`, add to the `agent` service:
```yaml
environment:
  - WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

---

## Stopping the system

```bash
# Stop everything (keep data)
docker compose down

# Stop and delete all data (clean reset)
docker compose down -v
```

---

## Security note

> This system contains an **intentionally vulnerable** application (DVWA). Deploy it only in an isolated lab/test environment. **Do not expose port 80 to the public Internet.** The Security Group must be restricted to your IP.
