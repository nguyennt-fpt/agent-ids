# Thiết kế thí nghiệm — agent-ids Giai đoạn 2

Tài liệu này giữ **cốt lõi khoa học** của dự án trong repo, để mọi session/người đọc hiểu *tại sao* thiết kế như vậy mà không cần plan file ẩn. Checklist triển khai: [../ROADMAP.md](../ROADMAP.md).

## Câu hỏi nghiên cứu

> AI agent (LLM + memory) có thực sự cải thiện chất lượng phát hiện/phản ứng so với IDS rule-based (Suricata) thuần không, và cải thiện ở đâu, đánh đổi gì?

## Insight quyết định toàn bộ: agent chỉ thắng ở 3 chỗ IDS yếu

Nếu corpus chỉ có tấn công rõ ràng → Suricata bắt ~100% → số liệu chứng minh agent *vô dụng*. Vì vậy thí nghiệm phải xây quanh 3 điểm yếu của rule-based:

| Điểm yếu rule-based | Agent thắng nhờ | Số liệu |
|---|---|---|
| Evasion/obfuscation (URL-encode kép, `/**/`, case-mix, base64) | Hiểu ngữ nghĩa | ↑ Recall |
| False positive (từ khóa giống attack nhưng benign) | Hiểu ngữ cảnh | ↓ FPR |
| Multi-step (1 req benign, 50 req/s = recon) | Nhìn chuỗi sự kiện | ↑ phát hiện scan |

## Kiến trúc "2 nguồn" (vì sao agent vừa ↓FP vừa ↑Recall)

```
Suricata ──▶ Nguồn 1: eve.json (high-signal, có thể miss evasion)
                                                          ├──▶ AGENT ──▶ block/warn/log
Nginx    ──▶ Nguồn 2: access.log (broad, bắt cái Suricata miss)
```

- `rule_based`/`naive` chỉ thấy `eve.json` → kế thừa recall của Suricata.
- `agent` đọc thêm nginx access log (`main.collect_agent_events`, nguồn "web") → bắt cái Suricata không alert → ↑recall. Đây là chỗ "IDS và agent bổ trợ nhau".

## 3 cấu hình so sánh (biến `RESPONSE_MODE`)

| Mode | Logic | Vai trò |
|---|---|---|
| `rule_based` | eve.json; block nếu severity ≤ 2 | IDS truyền thống + auto-response |
| `naive` | eve.json; block MỌI alert | Baseline thô (over-block) |
| `agent` | LLM + 2 nguồn | Phương pháp đề xuất |
| `agent_ids` | cùng LLM, chỉ eve.json | Ablation (E1): phần thắng của `agent` đến từ nguồn 2 hay từ suy luận |
| `waf` | OWASP CRS (ModSecurity, trong đường đi, DetectionOnly) | Baseline chuẩn doanh nghiệp: tấn công web thường được chặn bằng WAF, không phải NIDS |

## Cách đo công bằng

- Đo ở **tầng quyết định** (không phải iptables), vì traffic từ 1 IP.
- Mỗi request có **`eid` duy nhất** nhúng trong query string → truy vết qua `eve.json` và SQLite.
- Quyết định nhị phân malicious(block/warn) vs benign(log/ignore) → so ground-truth → Precision/Recall/F1/FPR + **MTTB**.
- **Benign vắng mặt:** request benign không match rule → không có entry eve.json → đối chiếu danh sách `eid` đã gửi (vắng = benign), không chỉ đọc eve.json.
- **Sync:** chờ tất cả `eid` vào SQLite (hoặc timeout) trước khi score (tránh race polling 5s).
- **Khoa học:** LLM non-deterministic → N=5 lần, báo cáo mean ± std. **Không hứa con số trước.**
- **Bất định do mẫu:** std qua N run không đo được việc corpus chỉ có ~100 request → báo cáo thêm 95% CI bootstrap
  ghép cặp theo request (`benchmark/bootstrap_ci.py`); khẳng định "agent > rule_based" chỉ khi CI của chênh lệch không chứa 0.
- **Ruleset IDS:** ET Open + custom rules. Số liệu chính dùng bản tinh chỉnh tối thiểu (`ids/rules/disable.conf`: chỉ tắt
  rule không nạp được và rule `2221036` — bắn trên phản hồi của chính DVWA, kể cả request benign). Tinh chỉnh áp như
  nhau cho mọi mode. **Phụ lục:** chạy lại trên ET Open nguyên bản (`disable-untuned.conf`) để chứng minh kết luận không
  dựa vào việc tinh chỉnh (quyết định 2026-10-25, phương án (ii)).

## Chống bias (rủi ro nghiêm trọng nhất)

Tôi vừa viết rule, vừa viết prompt — nếu tự chế corpus dễ "dựng để AI thắng". Biện pháp:
- Payload từ **nguồn công khai độc lập** (PayloadsAllTheThings, PortSwigger, OWASP), ghi cột `source`.
- Corpus evasion tách khỏi quá trình viết Suricata rule.

## Vì sao KHÔNG dùng CICIDS2017/NSL-KDD làm chính

Đó là network-flow features đã trích xuất (packet count, duration...), không phải HTTP payload thô → không khớp hệ thống phân tích payload-semantics. Corpus web-attack tự thiết kế kiểm soát chính xác 3 nhóm điểm yếu. (CICIDS → Future Work nếu mở rộng network-layer.)

## Trụ 4B — rule tự sinh: ĐÃ CẮT khỏi phạm vi (2026-10-25, quyết định E2)

Không đo, không báo cáo; code (`rule_validator`, `ids_manager`, golden set, bảng dashboard) đã xóa 2026-10-25. Lý do:
pipeline không có đường chạy (không gì gọi chúng từ khi bỏ MCP; container agent không có binary `suricata`), gate 2/3 chỉ mô phỏng bằng regex trên 14–20 mẫu nên ngưỡng
precision ≥ 0.95 không có ý nghĩa thống kê. Làm thật cần sidecar Suricata + pcap. Giữ lại dưới dạng Future Work —
thiết kế dự định (còn hợp lệ nếu làm sau):

Validation pipeline 4 gate (không tin mù output LLM):
1. **Syntax** — `suricata -T -S candidate.rules` offline, fail → reject.
2. **Shadow/canary** — rule chỉ `alert`; replay held-out → precision riêng ≥ 0.95 mới promote.
3. **Regression** — chạy lại golden set cố định; F1 giảm → REJECT + rollback (đảm bảo monotonic improvement).
4. **Runtime guardrail** — FP vượt ngưỡng → auto-disable; audit trail; tùy chọn human-in-the-loop.

"Tiến hóa tích cực" đo bằng: qua epoch `#active rules ↑`, `Recall ↑`, `FPR` phẳng, `MTTB ↓`. Rule đánh giá trên held-out **khác** data sinh nó → tránh overfit.

## Tiêu chí thành công

`report/summary.csv` cho thấy agent thắng F1 tổng hợp (↓FPR + ↑Recall) dù MTTB cao hơn (tradeoff trung thực); bypass_rate giảm sau defense; MITRE accuracy đo được; learning curve memory-on dốc xuống vs memory-off phẳng. Mọi số liệu dạng mean ± std (N=5).
