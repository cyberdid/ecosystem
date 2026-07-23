# Loops — evaluated automation candidates

Кожен loop = **trigger + bounded task + approved context + capability set + policy decision + attempt + independent gate + state + budget + approval + audit trail + hard stop + incident owner**. Новий loop спершу запускається вручну й проходить repeated-run evaluation. Колір не замінює D/A/Z/P policy classification.

| Loop | Колір | Automation | Skill | State | Gate | Статус |
|------|-------|-----------|-------|-------|------|--------|
| wiki-health-check | 🟢 | лише manual `eco run` / `eco eval` | вбудований fixed contract | HMAC SQLite + versioned report | 5 стабільних runs + zero-read replay | L2 implemented; без schedule |
| ml-autoresearch | 🟢 | нічний прогін на spark-ts (план) | — | git-лог експериментів | `val_bpb < baseline` | кандидат |

Метрики: cost per accepted change, repeated-run pass rate, unauthorized-action rate, human-review time та recovery rate. M4 gate завершений лише для read-only `wiki-health-check`; будь-який production/external-write loop потребує власних enforcement, approval та promotion gates.

Повний контракт, state machine, рівні L0–L5 та критерії запуску описані у [wiki/loops.md](../wiki/loops.md). `wiki-health-check` — ручний L2 profile, не автономний сервіс; `ml-autoresearch` залишається кандидатом.
