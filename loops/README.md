# Loops — evaluated automation candidates

Кожен loop = **trigger + bounded task + approved context + capability set + policy decision + attempt + independent gate + state + budget + approval + audit trail + hard stop + incident owner**. Новий loop спершу запускається вручну й проходить repeated-run evaluation. Колір не замінює D/A/Z/P policy classification.

| Loop | Колір | Automation | Skill | State | Gate | Статус |
|------|-------|-----------|-------|-------|------|--------|
| wiki-health-check | 🟢 | `/schedule` 07:00 (план) | `skills/wiki-health-check` (план) | versioned report | `wiki-lint.sh` → 0 broken | кандидат |
| ml-autoresearch | 🟢 | нічний прогін на spark-ts (план) | — | git-лог експериментів | `val_bpb < baseline` | кандидат |

Метрики: cost per accepted change, repeated-run pass rate, unauthorized-action rate, human-review time та recovery rate. Будь-який production/external-write loop залишається disabled до M3/M4 enforcement і approval gates.

Повний контракт, state machine, рівні L0–L5 та критерії запуску описані у [wiki/loops.md](../wiki/loops.md). Поточні записи є кандидатами, а не активними автономними сервісами.
