# MAP — карта екосистеми

> Оновлено: 2026-07-14. Порти/сервіси spark-ts — станом на dgx_spark AGENTS.md (2026-05-30); перевіряти перед використанням.

## Машини

| Вузол | Що | Доступ |
|-------|----|--------|
| **Windows PC** | робоча станція (Windows 11), WSL2 + Docker Desktop | локально |
| **WSL2 Ubuntu-24.04** | Linux-середовище на Windows PC; всі клони в `~/projects/` | `wsl` |
| **Mac** | друга станція; проксі-інструменти (copilot-vllm-proxy), історично SSH-хаб до spark-ts | — |
| **spark-ts** | NVIDIA DGX Spark: Blackwell GB10, 65 GB VRAM / 121 GB unified, ARM 20 ядер, Ubuntu 24.04, CUDA 13 | `ssh spark-ts` (Tailscale `100.92.223.21`) |
| **sirena RPi** | дрон-вузол (GPS hub, відеострімінг) | ssh `192.168.110.71` (креденшели — НЕ тут) |

## Сервіси spark-ts (порти)

| Порт | Сервіс |
|------|--------|
| `:4000` | **LiteLLM** — модельний шлюз (основа L1; аліаси claude-* → локальні вже працюють) |
| `:8001` | TRT-LLM GPT-OSS 120B Eagle3 (direct, ~40 tok/s) |
| `:8002` | gpt-oss-proxy (channel format → OpenAI tool_calls) |
| `:8003` | vLLM Qwen3.6 35B-A3B heretic NVFP4 + DFlash (84–118 tok/s) |
| `:11434` | Ollama (nemotron-3-super:120b + cloud моделі) |
| `:8082` | free-claude-code проксі |
| `:8080` | NemoClaw OpenShell кластер |
| `:8000` / `:3000` | Chatbot API (FastAPI) / Spark Chat UI (Next.js) |
| `:5432` | PostgreSQL 15 |
| — | **Hermes Agent** (Telegram `@dgx_spark_ts_bot`) — кандидат в оркестратори (Phase 5); k3s |

⚠️ GPU-конфлікт: `trtllm-eagle3` і `vllm-dflash` не працюють одночасно — зупиняй один перед стартом іншого.

## Репозиторії (github.com/Pylypko1021)

| Репо | Роль в екосистемі |
|------|-------------------|
| **ecosystem** (цей) | хаб: конституція, контракти, skills, mcp, loops, wiki |
| dgx_spark | вузол «машина DGX»: wiki (29 стор.), корпус доків (`docs/CORPUS.md` + `refresh-docs.sh`), скіли inference/ml/platform |
| LLM | сабмодулі karpathy/autoresearch + nanochat (Karpathy loop — кандидат Loop #2) |
| ML, voice-id-claude, voice-id-copilot | діаризація мовців / voice-id з агентною оркестрацією |
| drone_ops, gerbera (=Sirena), rpanion, Robonode, kansas, nat-project | дрон-кластер — споживач екосистеми, поза AI-ядром |

Сторонні референси: odysseus (pewdiepie-archdaemon) — приклад self-hosted AI-воркспейсу, розгорнутий у WSL2 (не наш проєкт); obra/superpowers — еталон мультихарнесної методології.

## Харнеси (куди синкаються скіли)

skillfish ставить у: Claude Code (`~/.claude/skills`), Codex (`~/.codex/skills`), GitHub Copilot (`~/.github/skills`), Gemini CLI (`~/.gemini/skills`), Antigravity (`~/.gemini/antigravity/skills`). Додатково: OpenCode, Continue (конфіги в dgx_spark).

## Корпус документації (raw-шар знань)

`dgx_spark/docs/` — маніфест `CORPUS.md`, оновлення `refresh-docs.sh`:
- `github-docs/` — GitHub docs (3 718 md + 3 782 data, CC-BY-4.0)
- `claude-code-docs/` — Claude Code EN (`llms-full.txt`, 163 сторінки)
- `hermes-agent-docs/` — NousResearch/hermes-agent docs (MIT)
- `x-articles/` — 12 статей: loops, self-improving KB, .claude anatomy, /goal
