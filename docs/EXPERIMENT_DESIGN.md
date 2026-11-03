# Experiment design — agent-ids Phase 2

This document keeps the project's **scientific core** in the repo, so any reader can understand *why* it is designed
this way without a hidden plan file.

## Research question

> Does an AI agent (LLM + memory) actually improve detection/response quality over a plain rule-based IDS (Suricata),
> and if so, where, and at what cost?

## The insight that drives everything: the agent can only win where the IDS is weak

If the corpus contained only clear attacks, Suricata would catch ~100% and the numbers would show the agent is
*useless*. So the experiment is built around 3 weaknesses of rule-based detection:

| Rule-based weakness | Agent wins through | Metric |
|---|---|---|
| Evasion/obfuscation (double URL-encoding, `/**/`, case-mix, base64) | Understanding semantics | ↑ Recall |
| False positives (attack-like keywords that are benign) | Understanding context | ↓ FPR |
| Multi-step (1 request is benign, 50 req/s = recon) | Seeing the sequence of events | ↑ scan detection |

## The "two sources" architecture (why the agent can both ↓FP and ↑Recall)

```
Suricata ──▶ Source 1: eve.json (high-signal, may miss evasion)
                                                          ├──▶ AGENT ──▶ block/warn/log
Nginx    ──▶ Source 2: access.log (broad, catches what Suricata misses)
```

- `rule_based`/`naive` only see `eve.json` → they inherit Suricata's recall.
- `agent` also reads the nginx access log (`main.collect_agent_events`, source "web") → catches what Suricata does not
  alert on → ↑recall. This is where "the IDS and the agent complement each other".

## The compared configurations (the `RESPONSE_MODE` variable)

| Mode | Logic | Role |
|---|---|---|
| `rule_based` | eve.json; block if severity ≤ 2 | Traditional IDS + auto-response |
| `naive` | eve.json; block EVERY alert | Crude baseline (over-blocking) |
| `agent` | LLM + 2 sources | Proposed method |
| `agent_ids` | same LLM, eve.json only | Ablation (E1): does `agent`'s gain come from source 2 or from reasoning |
| `waf` | OWASP CRS (ModSecurity, inline, DetectionOnly) | Enterprise-standard baseline: web attacks are usually stopped by a WAF, not a NIDS |

## Fair measurement

- Measure at the **decision layer** (not iptables), since the traffic comes from one IP.
- Every request carries a **unique `eid`** in its query string → traced through `eve.json` and SQLite.
- Binary decision malicious (block/warn) vs benign (log/ignore) → compared with ground truth →
  Precision/Recall/F1/FPR + **MTTB**.
- **Absent benign requests:** a benign request that matches no rule has no eve.json entry → compare against the list of
  sent `eid`s (absent = benign), not just eve.json.
- **Sync:** wait until every `eid` is in SQLite (or a timeout) before scoring (avoids racing the 5 s poll).
- **Rigor:** LLMs are non-deterministic → N=5 runs, report mean ± std. **No numbers promised in advance.**
- **Sampling uncertainty:** the std over N runs does not capture that the corpus has only ~100 requests → also report
  a 95% CI from a request-paired bootstrap (`benchmark/bootstrap_ci.py`); claim "agent > rule_based" only when the CI
  of the difference excludes 0.
- **IDS ruleset:** ET Open + custom rules. The main numbers use a minimally tuned version (`ids/rules/disable.conf`:
  only turns off rules that fail to load and rule `2221036` — it fires on DVWA's own responses, benign requests
  included). The tuning applies equally to every mode. **Appendix:** re-run on untuned ET Open
  (`disable-untuned.conf`) to show the conclusions do not depend on the tuning (decided 2026-10-25, option (ii)).

## Guarding against bias (the most serious risk)

The same person writes the rules and the prompt — a self-made corpus could easily be "built for the AI to win".
Countermeasures:
- Payloads come from **independent public sources** (PayloadsAllTheThings, PortSwigger, OWASP), recorded in a
  `source` column.
- The evasion corpus is kept separate from writing the Suricata rules.

## Why CICIDS2017/NSL-KDD is NOT the main dataset

Those are pre-extracted network-flow features (packet count, duration...), not raw HTTP payloads → they do not fit a
system that analyzes payload semantics. A purpose-built web-attack corpus controls the 3 weakness groups precisely.
(CICIDS → Future Work if extending to the network layer.)

## Pillar 4B — self-generated rules: CUT from scope (2026-10-25, decision E2)

Not measured, not reported; the code (`rule_validator`, `ids_manager`, golden set, dashboard table) was deleted on
2026-10-25. Reasons: the pipeline had no execution path (nothing called it after MCP was dropped; the agent container
has no `suricata` binary), and gates 2/3 were only simulated with regexes on 14–20 samples, so a precision ≥ 0.95
threshold has no statistical meaning. Doing it for real needs a Suricata sidecar + pcaps. Kept as Future Work — the
intended design (still valid if done later):

A 4-gate validation pipeline (never trust LLM output blindly):
1. **Syntax** — `suricata -T -S candidate.rules` offline; fail → reject.
2. **Shadow/canary** — the rule only `alert`s; replay held-out data → promote only at precision ≥ 0.95.
3. **Regression** — re-run a fixed golden set; F1 drops → REJECT + rollback (guarantees monotonic improvement).
4. **Runtime guardrail** — FP above a threshold → auto-disable; audit trail; optional human-in-the-loop.

"Positive evolution" is measured as: across epochs `#active rules ↑`, `Recall ↑`, `FPR` flat, `MTTB ↓`. Rules are
evaluated on held-out data **different** from the data that generated them → avoids overfitting.

## Success criteria

`report/summary.csv` shows the agent winning on overall F1 (↓FPR + ↑Recall) despite a higher MTTB (an honest
trade-off); bypass_rate drops with the defenses; MITRE accuracy is measurable; the memory-on learning curve slopes
down while memory-off stays flat. Every number as mean ± std (N=5).
