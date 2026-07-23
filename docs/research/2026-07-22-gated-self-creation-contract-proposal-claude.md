# Контракт Gated Self-Creation (GSC) — пропозиція

**Дата:** 2026-07-22
**Автор:** Claude (Fable 5), Claude Code
**Статус:** дизайн-пропозиція; не ухвалена архітектура, не runtime-зміна. Кандидат на окремий milestone (M7-рівень).
**Мета:** дати невідомій команді з невідомим LLM на невідомому проекті **генерацію** скілів, агентів і loops під їхні запити — так, щоб кожен згенерований артефакт підкорявся концепціям проєкту незалежно від їхньої моделі.
**Спирається на:** M6.2 skills registry, M6.3 loop engine + M4 promotion gate, M6.6 `AgentTeamManifest`, конституційні правила VERIFIED-STATE / BOUNDED-LOOPS / POLICY-OUTSIDE-PROMPTS / AUTHORITY-PRECEDENCE.

---

## 1. Проблема

Канонічний набір скілів (сьогодні 3) покриває лише відоме наперед. Невідома команда має власні запити й домен — **запастись усіма скілами неможливо, потрібна генерація.** Те саме для агентів (більшість не вміє їх писати) і loops (більшість не знає, що це, працюючи з LLM). Проєкт має вирішувати це за них.

Але наївна генерація (як у Hermes «writes its own SKILL.md», Superpowers «writing-skills meta») порушує **третій закон — немає спроможності без верифікації**. Скіл/агент/loop, що «самостворився» без перевірки, — це спроможність без доказу, тобто некерований артефакт, який робитиме що завгодно на невідомому LLM.

**Розв'язок — не «самостворення», а «самопропозиція + gate».** Артефакт генерується автоматично, але не набуває виконуваності, доки не пройде той самий шлях, що канонічний.

## 2. Принцип

> Генерація вільна. Промоушн — за доказом. Виконання — лише для промотованого.

Три стани довіри до будь-якого self-created артефакту:

- **proposed** — існує як текст/чернетка. Прав немає. Виконати не можна.
- **promoted** — пройшов gate, записаний у реєстр з owner і provenance. Виконуваний у межах.
- **revoked** — відкликаний; лишається в історії як доказ, але не виконуваний.

Це рівно модель, що вже діє для канонічних скілів (`revocation` поле в `registry.json`) і loops (M4 promotion). GSC поширює її на **генерацію під запит**.

## 3. Спільна машина станів (для skill / agent / loop однакова)

```text
[trigger: запит без наявного артефакту]
   → generate        (агент/модель пропонує артефакт + його власні тести)
   → bind            (provenance: хто згенерував, коли, digest, під який запит)
   → validate        (schema + contract: структура валідна)
   → narrow-check    (capabilities/budget ⊆ політики команди — AUTHORITY-PRECEDENCE)
   → deterministic-gate   (тести артефакту проходять; відтворюваність)
   → adversarial-gate     (validate-the-judge: атака на артефакт)
   → owner-bind      (accountable identity приймає власність — VERIFIED-STATE)
   → promote         (запис у реєстр; тепер виконуваний)
   → [active] ⇄ revoke
```

Кожен перехід fail-closed. Провал будь-якого gate → артефакт лишається `proposed`, з durable причиною. Ніколи не «тихо прийнято».

**Критичний gate — adversarial** (прямо з міграційних статей Anthropic + Karpathy/ADK: «validate the judge against broken code»): артефакт має пройти не лише позитивний тест, а й **атаку**. Скіл — спробу змусити його порушити hard-stop. Loop — спробу не збігтися/перевитратити бюджет. Агента — спробу вийти за capabilities. Артефакт, чий gate не ловить зумисно зламану версію, — не gate, і промоушн відхиляється.

## 4. Три артефакти

### 4.1 Skill self-creation

| Крок | Що конкретно |
|---|---|
| **Proposer** | Агент, зустрівши запит без наявного скіла, генерує `SKILL.md` (frontmatter name/description + процедура + **hard stop**) і **власний тест-контракт** (що скіл має робити / чого ніколи) |
| **Artifact** | Кандидат-запис у `skills.ai.ecosystem/v1alpha1` з усіма обов'язковими полями реєстру: `capabilities`, `dependencies`, `tests[]`, `evidence[]`, `owner`, `compatibility`, `contentDigest` |
| **Deterministic gate** | schema-valid; `tests[]` проходять; `contentDigest` стабільний; `capabilities ⊆` дозволених політикою команди |
| **Adversarial gate** | окремоконтекстний рецензент атакує: чи можна змусити скіл записати секрет / перезаписати unmanaged / обійти broker (hard-stop із канону `ecosystem-contract-change`) |
| **Evidence** | прогін тестів + adversarial-вердикт, збережені як `evidence[]` |
| **Owner** | людина (або делегована accountable identity) приймає власність — без owner немає promote |
| **Ефект** | `eco skills sync` розкладає новий скіл у всі харнеси команди (той самий M6.2 механізм) |

Реалізаційна прив'язка: розширити `src/eco_skills/` командою `eco skills propose` (генерує кандидата) + `eco skills promote` (ганяє gate, за успіху додає в registry). Реєстр уже має `revocation` — self-created скіл revocable з коробки.

### 4.2 Agent/role self-creation

| Крок | Що конкретно |
|---|---|
| **Proposer** | Агент пропонує роль у `AgentTeamManifest` (M6.6): `capabilities`, `budget`, `delegatesTo`, `notAfter`, прив'язку до `PrincipalIdentity`/`MembershipBinding` (M5) |
| **Deterministic gate** | `budget ⊆` бюджету команди; `capabilities ⊆` політики; `delegatesTo` вказує на наявні ролі; identity M5-підписана; `notAfter ≤` дедлайну команди (усе це вже валідує `eco_teams/contracts.py`) |
| **Adversarial gate** | рецензент перевіряє: чи нова роль може ескалувати права через `delegatesTo`-ланцюг; чи сумарний бюджет ролей не пробиває командний; separation-of-duties не порушено |
| **Owner** | людина підтверджує identity-binding (M5 — це вже криптографічна ідентичність, не «soul»-файл) |
| **Ефект** | роль стає частиною команди, координованої `TeamCoordinator`, у межах M5-authority |

Ключова відмінність від статей: агент — **не «soul»-файл із самонаписаною пам'яттю-як-авторитетом**, а M5-ідентичність із бюджетом і межами. VERIFIED-STATE: пам'ять агента ≠ його права.

### 4.3 Loop self-creation

| Крок | Що конкретно |
|---|---|
| **Proposer** | Агент пропонує loop-profile: trigger, body (який скіл), gate (об'єктивна перевірка), hard-stop, budget-per-attempt (структура `eco_loops/contracts.py`) |
| **Deterministic gate** | профіль schema-valid; `reserve_*_per_attempt ≤ max_*`; gate незалежний від body; side-effect-mode оголошено |
| **Adversarial gate** | **вже існує як M4 promotion**: 5 спроб + replay, L0-L2 eligibility. Розширення: сам профіль проходить gate *до* першого прогону; loop-until-dry дедупить проти *всього побаченого* (з graph-статті) |
| **Owner** | accountable identity + колір ризику (🟢/🟡/🔴); 🔴 loops (гроші/прод/аутбаунд) ніколи не авто-промотуються |
| **Ефект** | `eco loops run` виконує в межах; promotion L0→L2 лише за відтворюваним доказом |

Loop — найзріліший випадок: M4 gate вже робить 80% роботи. GSC додає лише «генерація самого профілю під запит» перед наявним промоушном.

## 5. Спектр автономності (обов'язковий вибір межі)

«Самостворення вночі» зі статей — це максимум автономії. Проєкт має **явну шкалу**, і команда обирає рівень:

| Рівень | Хто пропускає в реєстр | Коли доречно |
|---|---|---|
| 🟢 **L0 human-approve** | Агент пропонує → **людина підтверджує** (M3-style single-use approval) → promote | За замовчуванням; D2+ дані; будь-що незворотне |
| 🟡 **L1 auto-gate** | Агент пропонує → deterministic+adversarial gate авто → promote, **людина-owner post-hoc** accountable | Артефакти з *детермінованим* gate (більшість скілів/loops); низький ризик |
| 🔴 **L2 full-auto без owner** | — | **Заборонено.** Порушує VERIFIED-STATE і accountability. Немає такого рівня. |

Тобто автономне «самостворення» можливе (L1) — але **тільки для артефактів, чий gate детермінований, і завжди з accountable owner**. Немає артефакту без людини, яка за нього відповідає, навіть якщо вона не писала жодного рядка.

## 6. Ключові інваріанти

1. **Пропозиція ≠ права** (VERIFIED-STATE). `proposed` артефакт не виконується.
2. **Narrowing-only** (AUTHORITY-PRECEDENCE). Self-created не може розширити політику команди — лише діяти в її межах.
3. **Adversarial обов'язковий** (validate-the-judge). Промоушн вимагає, щоб gate ловив зумисно зламану версію артефакту.
4. **Accountable owner завжди** — навіть на L1. Промоушн без owner неможливий.
5. **Provenance незмінна** — хто (яка модель/агент), коли, під який запит, який digest, які докази. Audit-chain.
6. **Revocable завжди** — будь-що self-created можна відкликати; історія лишається доказом.
7. **Model-agnostic gate** — gate перевіряє *артефакт і його вихід*, не довіряє *генеруючій моделі*. Тому працює на будь-якому їхньому LLM.

## 7. Що це дає сценарію «невідома команда / LLM / проект»

- Їхній агент **генерує** скіл/loop/агента під їхній домен — вони не мусять уміти їх писати (твоя теза «більшість не знає»).
- Кожен згенерований артефакт **проходить gate, незалежний від їхнього LLM** — слабка чи ненадійна модель не проб'є концепції, лише отримає відмову промоушну.
- Вони отримують **не рій, що сам себе пише**, а **бібліотеку спроможностей, що росте під наглядом контрактів**, які ти заклала.
- «Переконатись, що концепції виконуються» = ланцюг доказів на кожному промоушні (provenance + test-evidence + adversarial-вердикт + owner + audit), а не довіра до їхньої моделі.

Це і є місток між тим, що є (канонічні скіли + M4/M6 примітиви), і тим, що ти описуєш (генерація під запит за твоїми концепціями).

## 8. Реалізаційний план (мапінг на код, орієнтовно)

1. **Спільне ядро GSC** — `src/eco_gsc/` (або в `eco_runtime`): машина станів §3, provenance-record, adversarial-gate-раннер.
2. **Skill** — `eco skills propose|promote` над наявним `eco_skills/`.
3. **Loop** — розширити `eco_loops` генерацією профілю перед наявним M4 promotion.
4. **Agent** — `eco team propose-role` над `eco_teams` + M5-identity binding.
5. **Adversarial suite** — спільний із раніше запропонованим enforcement-suite; кожен артефакт-тип має свій набір атак.
6. **Схеми** — `*-proposal.schema.json` для кожного типу; promotion пише в наявні реєстри з `revocation`.

Кожен пункт — окремий контракт із тестами й evidence (сам GSC підкоряється власним правилам).

## 9. Межі та non-claims

- Це **пропозиція**, не реалізація. Жоден рядок не написаний; жоден артефакт не промотований.
- GSC **не** робить слабку модель компетентною — він гарантує, що некомпетентний/ненадійний вихід не пройде gate, не що вихід буде корисним.
- GSC **не** дає повної автономії (L2 заборонено). Accountable owner обов'язковий завжди.
- Adversarial gate **не** доводить відсутність усіх дефектів — лише що артефакт витримує визначений набір атак. Prompt-injection-імунітет не заявляється.
- Реальна вартість adversarial-gate на кожен промоушн (токени/час) не виміряна; для великих команд може знадобитись кешування вердиктів.

## 10. Джерела

- `.ai/instructions.yaml` — VERIFIED-STATE, BOUNDED-LOOPS, AUTHORITY-PRECEDENCE, POLICY-OUTSIDE-PROMPTS
- `src/eco_skills/catalog/registry.json`, `src/eco_skills/schemas/skill-registry.schema.json`
- `src/eco_loops/contracts.py`, M4 promotion (`eco eval wiki-health-check`)
- `src/eco_teams/contracts.py` — `AgentTeamManifest`, M5 identity binding
- [Source review 2026-07-22](2026-07-22-agentic-teams-graphs-migrations-source-review.md) — validate-the-judge, graph-orchestration, чому framework self-writing відхилено
