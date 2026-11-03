# Benchmark — Trụ 1: A/B Evaluation Harness

Đo và so sánh **5 cấu hình phản ứng** trên cùng một corpus tấn công có nhãn, để chứng minh bằng số liệu AI agent cải thiện so với IDS rule-based thuần.

| Mode | Logic quyết định | Vai trò |
|---|---|---|
| `rule_based` | Suricata alert; block nếu `severity ≤ 2` | IDS truyền thống + auto-response |
| `naive` | Suricata alert; block **mọi** alert | Baseline thô (over-block) |
| `agent` | LLM + 2 nguồn (eve.json + nginx access.log) | Phương pháp đề xuất |
| `agent_ids` | cùng graph LLM, **chỉ eve.json** | Ablation: tách "thấy nhiều hơn" (nguồn 2) khỏi "suy luận tốt hơn" |
| `waf` | OWASP CRS trên ModSecurity (trong đường đi, DetectionOnly); tấn công khi rule `949110` (vượt ngưỡng anomaly) bắn | Baseline chuẩn doanh nghiệp cho tấn công web |

Thiết kế chi tiết & lý do: [../docs/EXPERIMENT_DESIGN.md](../docs/EXPERIMENT_DESIGN.md).

## Cách đo (tóm tắt)
- Mỗi request mang `eid` duy nhất trong query string → truy vết qua `eve.json` và SQLite decisions.
- Quyết định nhị phân: malicious (`block`/`warn`) vs benign (`log`/không có quyết định).
- So ground-truth (`label` trong corpus) → **Precision / Recall / F1 / FPR / Accuracy / MTTB**, kèm độ trễ
  `ttb_p95_s` (p95 time-to-block) và `undecided` (số request chưa có quyết định khi hết giờ chờ — bình thường 0).
- Request benign không sinh alert → không có entry → tính là dự đoán benign (đã xử lý trong `score.py`).
- LLM non-deterministic → chạy **N=5**, báo cáo **mean ± std**. std đó chỉ đo dao động của model trên *cùng*
  request; độ bất định do *chọn request nào* đo bằng **bootstrap ghép cặp theo request** (`bootstrap_ci.py`):
  lấy mẫu lại `eid` có hoàn lại, cùng mẫu cho mọi mode. Chênh lệch "mode − rule_based" chỉ là bằng chứng khi
  CI 95% không chứa 0.

## Chạy

```bash
# 0. Hệ thống đang chạy (xem ../README.md). Model:
#    - thật:   qwen2.5:14b  (EC2 GPU)
#    - test:   qwen2.5:3b   (local, đổi OLLAMA_MODEL trong docker-compose)
pip install -r requirements.txt
python attack_corpus/build_corpus.py     # sinh corpus.jsonl

# 1. Chạy toàn bộ A/B (5 mode × N lần) + tổng hợp + biểu đồ
N=5 TARGET=http://localhost bash run_ab.sh
#    SPLIT=dev khi chỉnh; SPLIT=test cho số cuối; SPLIT=held_out (tấn công chưa replay lúc chỉnh) một lần, ở cuối

# Kết quả:
#   report/summary_raw.csv  — mỗi dòng 1 run
#   report/summary.csv      — mean±std mỗi mode
#   report/preds.jsonl      — dự đoán từng eid mỗi run (đầu vào bootstrap)
#   report/ci.csv           — 95% CI bootstrap ghép cặp theo request, gồm "mode - rule_based"
#   report/calibration.csv  — confidence (= xác suất là tấn công) có khớp tỉ lệ tấn công thật không
#                             (ECE; + reliability.png nếu có matplotlib)
#   report/logs/<mode>_run<N>.log — log container agent mỗi run; mode agent* in thêm dòng [CALLS]
#                             (số lần gọi LLM: triage / bước điều tra / quyết định cuối / thử lại)
#   report/compare_quality.png, compare_mttb.png, compare_groups.png
# REPORT_TAG=<tên> → sao kết quả vào report/<tên>/ (lần chạy sau xóa các file ở report/)
```

### Số liệu cuối + phụ lục độ nhạy với tinh chỉnh IDS

Số liệu chính chạy trên ET Open **đã tinh chỉnh** (`ids/rules/disable.conf`: tắt Modbus/DNP3 — không nạp được — và
rule nhiễu `2221036`). Phụ lục chạy lại y hệt trên ET Open **nguyên bản** (`disable-untuned.conf`: chỉ tắt Modbus/DNP3)
để cho thấy kết luận không phụ thuộc vào việc tắt rule đó. Trên host EC2, từ gốc repo:

```bash
bash ids/update_rules.sh                      # bản tinh chỉnh (mặc định)
REPORT_TAG=main SPLIT=test N=5 bash benchmark/run_ab.sh
bash ids/update_rules.sh untuned              # ET Open nguyên bản
REPORT_TAG=etopen-untuned SPLIT=test N=5 bash benchmark/run_ab.sh
bash ids/update_rules.sh                      # trả về bản tinh chỉnh
```

`update_rules.sh` dừng với lỗi nếu suricata-update không cài được ruleset (nó âm thầm giữ lại bộ rule cũ khi
`suricata -T` thất bại), restart Suricata, rồi kiểm Ollama còn GPU không.

## Trụ 3 — Adversarial robustness (prompt injection)

Đo tỷ lệ **bypass** (tấn công thật mà quyết định cuối không phải block/warn) khi mỗi request đi qua **đúng đường
production**: `main.process_agent_events` → graph (structured output, salvage, investigate, act), gồm retry +
fail-closed. Hai lớp phòng thủ bật/tắt **độc lập** (thiết kế 2×2): phần DEFENSE trong `prompts/system.md`, và bọc
`<<UNTRUSTED_DATA>>` (`wrap_untrusted`). Event dạng nguồn web (không có signature IDS gợi ý). Mỗi batch ghép mẫu
injection với vài tấn công sạch của tập dev → đo cả **bypass lan sang** event khác trong batch. Không ghi DB, không
đụng firewall, tool điều tra thấy log rỗng. Mặc định agent triage **từng event** (`TRIAGE_BATCH=1`, N1) → mỗi event
một lần gọi model, lan sang = 0 theo cấu trúc; thêm `-e TRIAGE_BATCH=15` vào `docker exec` để đo lan sang khi gộp lô.

```bash
# chạy trong container agent (có langgraph + Ollama) — trên EC2:
docker cp benchmark agent:/tmp/bench
# MEMORY_ENABLED=false: container còn env của learning curve thì triage sẽ kèm lesson cũ
docker exec -e AGENT_DIR=/app -e MEMORY_ENABLED=false -e RESPONSE_MODE=agent agent \
  python /tmp/bench/adversarial/test_injection.py   # --repeats 2 --companions 3
docker cp agent:/tmp/bench/report/adversarial_graph.csv benchmark/report/
# -> bypass + bypass lan sang theo từng điều kiện, tác động riêng của từng lớp phòng thủ, kèm 95% CI
```

CI là bootstrap theo mẫu injection (các lần lặp của cùng một mẫu không độc lập). Bộ mẫu: **25** kỹ thuật trong 5 họ
(`injections.jsonl`, sinh từ `build_injections.py`; 12 mẫu đầu là bộ dùng tới 2026-10-27). Lớp parse cứng (action enum, fail-closed từng item, salvage) nằm trong
`agent/schemas.py` và luôn bật — không phải biến của thí nghiệm.

## Trụ 4 — Experience memory

Đo **learning curve**: agent học từ lỗi qua nhiều epoch (memory on vs off). Mỗi epoch **đánh giá trước** trên tập
test (chỉ dùng lesson đã học), **rồi học** từ feedback của tập dev — không bao giờ nạp đáp án của tập đang chấm
(bản cũ replay cùng corpus và nạp đáp án của chính các request đó → đo khả năng nhớ đáp án). Epoch 1 = mốc chưa có memory.

```bash
docker exec ollama ollama pull nomic-embed-text     # embedding cho memory
python learning_curve.py --epochs 3 --memory on --delay 4    # số trong README chạy đúng lệnh này
python learning_curve.py --epochs 3 --memory off --delay 4
# -> report/curve_on.csv, curve_off.csv, learning_curve.png (FPR↓ / Recall↑ theo epoch)
```

*Rule tự sinh (Trụ 4B, pipeline 4 gate) đã **cắt khỏi phạm vi** và xóa code — xem `docs/EXPERIMENT_DESIGN.md` mục "Trụ 4B".*

### Chạy tay từng bước (debug)
```bash
RESPONSE_MODE=agent BLOCK_ENABLED=false WEB_UNTAGGED=false docker compose up -d --force-recreate --no-deps agent
python replay.py --target http://localhost --delay 0.5
python score.py --mode agent --run 1
python plot.py
```

## Đọc kết quả
- `compare_quality.png` — Precision/Recall/F1/FPR/Accuracy theo mode (có error bar = std).
- `compare_groups.png` — **nơi agent nên thắng**: `recall_evasion` ↑ (bắt evasion Suricata miss) và `fpr_fpbait` ↓ (không chặn nhầm request trông giống attack).
  Kết quả 2026-11-03 (v4): thắng ở evasion (recall 1.00, WAF 0.88, IDS 0.27), không thắng ở fp_bait (FPR 0.08, WAF 0.07, IDS 0).
- `compare_mttb.png` — agent thường **chậm hơn** (LLM ~vài giây) — tradeoff trung thực.
- Nhịp replay: rule/WAF `DELAY` (0.5s), agent* `DELAY_LLM` (mặc định 6s). Triage từng event tốn ~4.4s LLM/request
  trên T4; nhịp 4s (2026-10-27) không còn dư → MTTB đo hàng đợi và một run tụt >10 phút. Giữ tải ≲75%.

## Lưu ý
- `BLOCK_ENABLED=false` khi benchmark để agent **ghi quyết định nhưng không** firewall nguồn replay (tránh tự chặn các request sau).
- Corpus: **260 mẫu** (159 tấn công / 101 lành; dev 52, test 147, held_out 61 — chỉ tấn công) từ nguồn công khai —
  `attack_corpus/build_corpus.py`. Tập test đã dùng cho ba lần đo cuối (2026-10-27, 2026-11-01, 2026-11-03), held_out
  một lần (2026-11-03) → đổi prompt/logic sau này cần tập mới, có cả request lành.
- `score.py` chờ quyết định trước khi chấm: mode `agent` chờ tới khi **mọi `eid` đã gửi** có quyết định;
  `rule_based`/`naive`/`agent_ids` chờ đủ các `eid` Suricata đã alert trong run này (`alerted_eids.py` →
  `--alerted`, `run_ab.sh` tự làm). Tối đa `--timeout` (mặc định 2700s — chỉ là chốt an toàn: một run chậm phải
  hiện ở độ trễ, không thành "bỏ sót"); hết giờ in số `eid` thiếu và ghi cột `undecided`. Chạy tay
  không có `--alerted` thì quay về "số row ổn định `--settle` giây".
- Mỗi run tạo lại container agent (`--force-recreate`) → tập `decided` và offset đọc log bắt đầu mới;
  agent đọc cả `eve.json` lẫn nginx log từ cuối file lúc khởi động (không xử lý lại traffic run trước).
- Host Ubuntu (EC2): tắt timer apt tự động, cập nhật tay lúc đầu phiên. apt tải gói qua HTTP → alert IDS rác chen vào
  hàng đợi agent (run timeout 2026-10-27); apt cài gói → Ollama mất GPU (`systemd`) hoặc driver NVIDIA lệch phiên bản,
  phải reboot (2026-11-01). Tắt: `sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer`. Trước khi đo:
  `sudo apt update && sudo apt upgrade -y` → reboot nếu có gói NVIDIA/systemd/kernel → `docker exec ollama nvidia-smi -L`.
