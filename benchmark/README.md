# Benchmark — Trụ 1: A/B Evaluation Harness

Đo và so sánh **3 cấu hình phản ứng** trên cùng một corpus tấn công có nhãn, để chứng minh bằng số liệu AI agent cải thiện so với IDS rule-based thuần.

| Mode | Logic quyết định | Vai trò |
|---|---|---|
| `rule_based` | Suricata alert; block nếu `severity ≤ 2` | IDS truyền thống + auto-response |
| `naive` | Suricata alert; block **mọi** alert | Baseline thô (over-block) |
| `agent` | LLM + 2 nguồn (eve.json + nginx access.log) | Phương pháp đề xuất |
| `agent_ids` | cùng graph LLM, **chỉ eve.json** | Ablation: tách "thấy nhiều hơn" (nguồn 2) khỏi "suy luận tốt hơn" |

Thiết kế chi tiết & lý do: [../docs/EXPERIMENT_DESIGN.md](../docs/EXPERIMENT_DESIGN.md).

## Cách đo (tóm tắt)
- Mỗi request mang `eid` duy nhất trong query string → truy vết qua `eve.json` và SQLite decisions.
- Quyết định nhị phân: malicious (`block`/`warn`) vs benign (`log`/không có quyết định).
- So ground-truth (`label` trong corpus) → **Precision / Recall / F1 / FPR / Accuracy / MTTB**.
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

# 1. Chạy toàn bộ A/B (3 mode × N lần) + tổng hợp + biểu đồ
N=5 TARGET=http://localhost bash run_ab.sh

# Kết quả:
#   report/summary_raw.csv  — mỗi dòng 1 run
#   report/summary.csv      — mean±std mỗi mode
#   report/preds.jsonl      — dự đoán từng eid mỗi run (đầu vào bootstrap)
#   report/ci.csv           — 95% CI bootstrap ghép cặp theo request, gồm "mode - rule_based"
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
đụng firewall, tool điều tra thấy log rỗng.

```bash
# chạy trong container agent (có langgraph + Ollama) — trên EC2:
docker cp benchmark agent:/tmp/bench
docker exec -e AGENT_DIR=/app agent python /tmp/bench/adversarial/test_injection.py   # --repeats 2 --companions 3
docker cp agent:/tmp/bench/report/adversarial_graph.csv benchmark/report/
# -> bypass + bypass lan sang theo từng điều kiện, tác động riêng của từng lớp phòng thủ, kèm 95% CI
```

CI là bootstrap theo mẫu injection (các lần lặp của cùng một mẫu không độc lập). Bộ mẫu hiện có **12** (`injections.jsonl`)
→ CI sẽ rộng; mở rộng bộ mẫu là việc riêng. Lớp parse cứng (action enum, fail-closed từng item, salvage) nằm trong
`agent/schemas.py` và luôn bật — không phải biến của thí nghiệm.

## Trụ 4 — Experience memory

Đo **learning curve**: agent học từ lỗi qua nhiều epoch (memory on vs off). *(Chưa dùng được cho kết luận:
learning curve còn rò rỉ đáp án — G1 trong `notes/checklist-2026-09.md`.)*

```bash
docker exec ollama ollama pull nomic-embed-text     # embedding cho memory
python learning_curve.py --epochs 5 --memory on
python learning_curve.py --epochs 5 --memory off
# -> report/curve_on.csv, curve_off.csv, learning_curve.png (FPR↓ / Recall↑ theo epoch)
```

*Rule tự sinh (Trụ 4B, pipeline 4 gate) đã **cắt khỏi phạm vi** và xóa code — xem `docs/EXPERIMENT_DESIGN.md` mục "Trụ 4B".*

### Chạy tay từng bước (debug)
```bash
RESPONSE_MODE=agent BLOCK_ENABLED=false docker compose up -d --force-recreate --no-deps agent
python replay.py --target http://localhost --delay 0.5
python score.py --mode agent --run 1
python plot.py
```

## Đọc kết quả
- `compare_quality.png` — Precision/Recall/F1/FPR/Accuracy theo mode (có error bar = std).
- `compare_groups.png` — **nơi agent nên thắng**: `recall_evasion` ↑ (bắt evasion Suricata miss) và `fpr_fpbait` ↓ (không chặn nhầm request trông giống attack).
- `compare_mttb.png` — agent thường **chậm hơn** (LLM ~vài giây) — tradeoff trung thực.

## Lưu ý
- `BLOCK_ENABLED=false` khi benchmark để agent **ghi quyết định nhưng không** firewall nguồn replay (tránh tự chặn các request sau).
- Corpus hiện là **seed (~60)**. Trước khi chạy số liệu cuối trên EC2, scale mỗi nhóm lên từ cùng nguồn công khai (xem `attack_corpus/build_corpus.py`, mục tiêu ~150).
- `score.py` chờ quyết định trước khi chấm: mode `agent` chờ tới khi **mọi `eid` đã gửi** có quyết định;
  `rule_based`/`naive`/`agent_ids` chờ đủ các `eid` Suricata đã alert trong run này (`alerted_eids.py` →
  `--alerted`, `run_ab.sh` tự làm). Tối đa `--timeout` (mặc định 600s), hết giờ in số `eid` thiếu. Chạy tay
  không có `--alerted` thì quay về "số row ổn định `--settle` giây".
- Mỗi run tạo lại container agent (`--force-recreate`) → tập `decided` và offset đọc log bắt đầu mới;
  agent đọc cả `eve.json` lẫn nginx log từ cuối file lúc khởi động (không xử lý lại traffic run trước).
