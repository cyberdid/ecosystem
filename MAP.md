# MAP — deployment inventory

> Оновлено: 2026-07-15. Це операційний inventory, не canonical architecture і не trust certificate. Дані про колишній DGX Spark збережені лише як історичний snapshot і не означають доступність сервісів.

## Машини

| Вузол | Що | Доступ |
|-------|----|--------|
| **Windows PC** | робоча станція (Windows 11), WSL2 + Docker Desktop | локально |
| **WSL2 Ubuntu-24.04** | Linux-середовище на Windows PC; всі клони в `~/projects/` | `wsl` |
| **Mac** | друга станція; проксі-інструменти (copilot-vllm-proxy), історично SSH-хаб до spark-ts | — |
| **spark-ts** | Колишній NVIDIA DGX Spark; вузол більше недоступний і не є ecosystem dependency | retired / unavailable |
| **sirena RPi** | дрон-вузол (GPS hub, відеострімінг) | ssh `192.168.110.71` (креденшели — НЕ тут) |

## Історичний snapshot сервісів spark-ts — не активний inventory

| Порт | Сервіс |
|------|--------|
| `:4000` | **LiteLLM** — наявний optional gateway; не source of truth і не обов'язковий execution path |
| `:8001` | TRT-LLM GPT-OSS 120B Eagle3 (direct, ~40 tok/s) |
| `:8002` | gpt-oss-proxy (channel format → OpenAI tool_calls) |
| `:8003` | vLLM Qwen3.6 35B-A3B heretic NVFP4 + DFlash (84–118 tok/s) |
| `:11434` | Ollama (nemotron-3-super:120b + cloud моделі) |
| `:8082` | free-claude-code проксі |
| `:8080` | NemoClaw OpenShell кластер |
| `:8000` / `:3000` | Chatbot API (FastAPI) / Spark Chat UI (Next.js) |
| `:5432` | PostgreSQL 15 |
| — | **Hermes Agent** (Telegram `@dgx_spark_ts_bot`) — optional external-agent adapter candidate; not core |

Ці записи збережено для provenance старих досліджень. Routing, health checks і deployment policy не повинні використовувати їх як активні endpoints.

## Репозиторії (github.com/Pylypko1021)

| Репо | Роль в екосистемі |
|------|-------------------|
| **ecosystem** (цей) | executable contracts/compiler/projections; embedded M2 read-only reference profile complete with trusted evidence, isolation, governed adapters, and live local/cloud evaluation under ADR-016's observable-identity boundary |
| dgx_spark | історичний приклад і корпус документації; не активний вузол та не dependency |
| LLM | сабмодулі karpathy/autoresearch + nanochat (Karpathy loop — кандидат Loop #2) |
| ML, voice-id-claude, voice-id-copilot | діаризація мовців / voice-id з агентною оркестрацією |
| drone_ops, gerbera (=Sirena), rpanion, Robonode, kansas, nat-project | дрон-кластер — споживач екосистеми, поза AI-ядром |

Сторонні референси: odysseus (pewdiepie-archdaemon) — приклад self-hosted AI-воркспейсу, розгорнутий у WSL2 (не наш проєкт); obra/superpowers — еталон мультихарнесної методології.

## Локальні upstream-клони

| Проєкт | Локальний шлях | Snapshot | Роль / статус |
|---|---|---|---|
| [TIGER-AI-Lab/OpenResearcher](https://github.com/TIGER-AI-Lab/OpenResearcher) | `/home/snow/projects/OpenResearcher` | `785fd6ba` | External experimental research node; source downloaded, not installed or running; [wiki](wiki/openresearcher.md) |
| [NVIDIA-NeMo/labs-molt](https://github.com/NVIDIA-NeMo/labs-molt) | `/home/snow/projects/labs-molt` | `a016f4ee` | External agentic-RL training node; source downloaded and statically reviewed, not installed or running; [wiki](wiki/labs-molt.md) |
| [zubair-trabzada/ai-legal-claude](https://github.com/zubair-trabzada/ai-legal-claude) | `/home/snow/projects/ai-legal-claude` | `19ece98d` | External Claude-specific legal prompt corpus; downloaded and statically reviewed, not installed; [wiki](wiki/ai-legal-claude.md) |

Upstream-клони не є довіреними ecosystem deployments. Їхні prompts, tools, retrieved content, dependencies і services проходять ті самі policy, provenance, sandbox та evaluation gates, що й будь-який зовнішній компонент.

## Поточний M2 evaluation snapshot

- Local reference: Ollama/Qwen on the governed WSL workstation; DGX is not required.
- Cloud reference: broker-owned Claude CLI with a governed provider model alias. The alias does not attest immutable cloud weights or backend revision.
- Live observation validity: 24 hours from `testedAt`; afterward the files remain historical evidence but require renewal before current routing or promotion.
- Retained evaluation records are raw-content-free D0 evidence. They omit raw prompt/response bodies but deterministic low-entropy digests may remain guessable.
- Closure details and exact authenticated digests are in `.ai/evals/live/2026-07-15-m2-closure-pass/`; earlier siblings are historical/superseded attempts.

## Харнеси (куди синкаються скіли)

skillfish ставить у: Claude Code (`~/.claude/skills`), Codex (`~/.codex/skills`), GitHub Copilot (`~/.github/skills`), Gemini CLI (`~/.gemini/skills`), Antigravity (`~/.gemini/antigravity/skills`). Додатково: OpenCode, Continue (конфіги в dgx_spark).

## Корпус документації (raw-шар знань)

`dgx_spark/docs/` — маніфест `CORPUS.md`, оновлення `refresh-docs.sh`:
- `github-docs/` — GitHub docs (3 718 md + 3 782 data, CC-BY-4.0)
- `claude-code-docs/` — Claude Code EN (`llms-full.txt`, 163 сторінки)
- `hermes-agent-docs/` — NousResearch/hermes-agent docs (MIT)
- `x-articles/` — 12 статей: loops, self-improving KB, .claude anatomy, /goal
