# Loops — реєстр

Дисципліна (див. `AGENTS.md` → Контракти → Loop): кожен loop = **automation + skill + state + gate + hard stop**. Колір 🟢/🟡/🔴. Новий loop спершу проганяється вручну, потім іде на розклад.

| Loop | Колір | Automation | Skill | State | Gate | Статус |
|------|-------|-----------|-------|-------|------|--------|
| wiki-health-check | 🟢 | `/schedule` 07:00 (план) | `skills/wiki-health-check` (план) | STATE.md | `wiki-lint.sh` → 0 broken | кандидат |
| ml-autoresearch | 🟢 | нічний прогін на spark-ts (план) | — | git-лог експериментів | `val_bpb < baseline` | кандидат |

Метрика здоров'я будь-якого loop: **cost per accepted change**. Прийнято <50% результатів → loop програє, вимкнути й переробити gate.
