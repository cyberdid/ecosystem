# Локальний сурогат-CI та фікси портативності — Claude

**Дата:** 2026-07-22
**Автор:** Claude (Fable 5), Claude Code — рецензент/виконавець цієї сесії
**Гілка:** `codex/m6-functional-orchestration` (PR #3 → `main`)
**Статус:** робоча нотатка; не заявка на завершення чи реліз
**Аудиторія:** власниця проєкту і наступний агент (Codex/Claude)

Причина сесії: GitHub Actions заблоковано білінгом акаунта (усі hosted-джоби падають за 2–3 с із «account is locked due to a billing issue»), тож M6 не має жодного зеленого hosted-прогону. Ця сесія відтворила перевірки локально на macOS і закрила портативні дефекти, знайдені при цьому.

## 1. Локальний сурогат-CI (macOS, Python 3.11 через uv)

Відтворено все, що не є Linux-only enforcement або live-LLM:

| Джоба CI | Локально | Результат |
|---|---|---|
| `portable-contracts` (точний список CI) | ✅ | **287 тестів OK** |
| `quality` · `eco validate/render --check/doctor` | ✅ | healthy, exit 0 |
| `quality` · `eco skills check --json` | ✅ | `synchronized` |
| `quality` · `scripts/check_m6_release_conformance.py` | ✅ | **`status: pass`** (leak/secret sentinel absent, repo identity unchanged, 411 tracked) |
| `distribution` · wheel build | ✅ | `ai_ecosystem_harness-0.8.0` |
| `distribution` · offline install smoke | ✅ | `eco 0.8.0` ставиться `--no-index`, `team`/`skills` працюють |
| `linux-full` (повна сюїта) | ❌ | Linux openat2/Landlock — потрібен WSL/Linux |
| `quality` · `pytest` | ⚠️ | падає лише на Linux-only write-брокерах; на ubuntu був би зелений |

Висновок: уся портативна частина M6 здорова на не-Linux хості; блокери релізу зовнішні (білінг) або платформні (openat2), не дефекти коду.

## 2. Фікси портативності (2 коміти)

Симптом: на macOS `/var` і `/tmp` — симлінки в `/private`. Рантайм і церемонія провізіювання легітимно відхиляють будь-який шлях, що проходить через симлінк (анти-symlink guard). Сирий `tempfile.TemporaryDirectory().name` тому спрацьовував цей guard на macOS, хоча на Linux CI тести зелені. Виправлення — нормалізувати корінь tmpdir через `Path(...).resolve()` (no-op на Linux); навмисні симлінки, які створюють самі тести, лишаються недоторканими.

| Коміт | Модуль | Було → стало |
|---|---|---|
| `cb2bc28` | `tests/test_m6_general_teams.py` | 24 error → **24 OK** (нормалізація tmpdir у `setUp`) |
| `1c37bc4` | `tests/test_m6_secure_provisioning.py` | 4 fail/error → **13 OK** (`_resolved_tempdir()` хелпер, 8 місць) |

Перевірка, що безпекові контракти не послаблені: навмисні symlink-тести (`test_observed_leaf_symlink…`, `test_external_output…` з `alias.symlink_to`, `test_publication_is_atomic…`) виконуються як `ok`, не skip і не false-pass. Регресія portable+обидва модулі = **205 OK**.

Ефект на повну сюїту macOS: **120 → 92 червоних** (−28).

## 3. Відкликання попередньої претензії (чесність)

У review pack від 2026-07-16 і усних звітах я стверджував, що `eco loops run`/`eco run` повертають `exit 0` при `failed`/`blocked` («пастка для cron»). **Це хибно.** Реальний код коректний:

```python
result = {"available": checkpoint.state == "succeeded", ...}
return 0 if result["available"] else 1
```

Перевірено без пайпа: `eco loops run wiki-health-check` → `State: failed` → **exit 1**; `eco run` без аргументів → exit 2 (argparse). Мій попередній «exit 0» був артефактом власної методики (`… | head; echo $?` бере код `head`, не `eco`). Дисципліна exit-кодів у CLI присутня; правку не робив.

## 4. Чесна класифікація залишкових 92 падінь macOS

Усі впираються в Linux openat2/Landlock enforcement, фізично відсутній на цьому хості:

- `write_broker` (20), `write_orchestrator` (15), `broker` (13), `evidence` (6), `isolation`, `snapshot` — openat2/Landlock за дизайном;
- `source_review_cli` (11) — `_LinuxAnchoredSourceReader` (openat2);
- `m4_wiki_execution` (18) — має tmpdir-крихкість (14 `LOCATION_DENIED`), **але** викликає `RepositoryReadBroker` (openat2), тож Linux-bound по суті. Нормалізація tmpdir лише зсунула б точку падіння на openat2 — тому не фіксив.

Після цієї сесії на macOS не лишилось «даремно червоних» тестів через непортативність: кожен із 92 означає рівно «потрібен Linux», а не «тест зламаний». Це чесна межа, якої раніше не було.

## 5. Що не зроблено / поза скоупом

- Повна Linux-сюїта та зелений hosted CI — потребують розблокованого білінгу Actions (публічний репо → Actions безкоштовні; лок треба зняти в акаунті), або прогону на WSL.
- Live 5-role source-review PASS — LLM-пауза за інструкцією власниці + потрібен GPU/сильніший backend (див. [handoff §6](2026-07-20-m6-live-dogfood-handoff-claude.md)).
- `extends` (org→profile→project) для company-scale — окрема робота.

## 6. Наступні кроки

1. Розблокувати GitHub billing → перший зелений hosted-ран → merge PR #3.
2. Role-instruction hardening (handoff §6.2) — перенести 4 дисциплінарні правила в пакетні інструкції ролі; наближає перший PASS без нового заліза.
3. Оцінка M6 після сурогат-CI: код у доброму стані (портативна частина зелена, conformance pass, offline-дистрибуція працює); залишкові блокери — операційні, не інженерні.
