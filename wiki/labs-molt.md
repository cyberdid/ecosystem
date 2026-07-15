# NVIDIA NeMo labs-molt — agentic RL training node

**Updated:** 2026-07-15
**Status:** source downloaded and statically reviewed; not installed, trusted, or running

## Snapshot

| Field | Value |
|---|---|
| Upstream | [NVIDIA-NeMo/labs-molt](https://github.com/NVIDIA-NeMo/labs-molt) |
| Local path | `/home/snow/projects/labs-molt` |
| Branch | `main` |
| Commit | `a016f4eeb71d024a1bfb11f921d5cf2c415aaa00` |
| Version in `version.txt` | `0.1.2` |
| License | Apache-2.0 |
| Downloaded | Source repository and Git history; 143 tracked files, approximately 3.5 MB checkout |
| Not downloaded or executed | Model weights, datasets, trajectories, Docker image, dependencies, Ray services, vLLM engines, GPU workloads |
| Ecosystem classification | External experimental training/evaluation node |

The checkout preserves its upstream `origin` and is clean. It is not an ecosystem deployment and is not represented in canonical `.ai/deployments.yaml`.

## What it is

Molt is a PyTorch-native harness for supervised fine-tuning and agentic reinforcement learning. A locally trainable policy model performs tasks through an agent or environment; Molt records token-exact trajectories, computes rewards and advantages, trains the policy with NVIDIA AutoModel/FSDP2, and broadcasts the new weights to vLLM rollout engines.

It is not a general assistant, vendor-neutral agent orchestrator, MCP platform, knowledge base, or replacement for the ecosystem core. It cannot train proprietary Claude, Codex, Copilot, or hosted API weights. Those systems may participate only through an adapter role such as judge, teacher, data generator, or external harness where policy and data rules allow it.

```text
task/dataset
→ Env or ChatAgent
→ vLLM rollout
→ token-exact Trajectory + reward
→ Ray async queue
→ advantage / KL / optional critic
→ AutoModel + FSDP2 policy update
→ weight broadcast to vLLM
→ next rollout
```

## Loop and harness interpretation

Molt contains two nested loops:

1. **Agent loop:** observation → model action → tool/environment feedback → next action → termination or truncation.
2. **Learning loop:** trajectories → reward → policy/value update → weight synchronization → new trajectories.

Molt is the specialized training harness around both loops: Ray placement and queues, vLLM generation, token and mask alignment, reward/advantage calculation, distributed optimization, checkpointing, evaluation, and observability.

This differs from the ecosystem's ordinary execution or automation loop. Molt changes model weights; it therefore belongs behind stronger data, evaluator, GPU-budget, artifact-provenance, and promotion gates.

## Agent contracts

Molt offers two public execution paths:

- `Env` + `StepEnvRunner`: Molt owns the model loop; user code implements Gymnasium-like `reset()` and `step()` and returns a `Result`.
- `ChatAgent` + `ChatAgentRunner`: user code owns the multi-turn loop through a standard OpenAI or Anthropic SDK pointed at a session-scoped loopback FastAPI server.

`Result` carries reward, observation, terminated/truncated state, optional score, info, images, and sampling overrides. `Trajectory` carries exact token IDs, action ranges, rollout log probabilities, multimodal training inputs, reward, identifiers, truncation, stale-token spans, and optional MoE routing selections.

The token-first contract is the project's strongest reusable design pattern. It avoids silently re-tokenizing generated text before training and keeps observation/tool tokens out of the policy-gradient mask.

## Runtime architecture

### Rollout plane

- vLLM engines generate token-in/token-out responses.
- A Rust `vllm-router` distributes requests and preserves session affinity.
- Ray runner actors execute agents and grading code.
- Multiple prompt groups remain in flight to keep rollout engines utilized.
- A bounded queue and slot tokens provide backpressure between generation and training.

### Training plane

- One trainable policy is distributed across an AutoModel/FSDP2 actor group; “single actor” does not mean one process or one GPU.
- Optional reference workers provide KL regularization or a distillation teacher.
- PPO/GAE adds an optional critic group and clipped value loss.
- TP, EP, CP, DP, CPU optimizer offload, activation checkpointing, and multimodal inputs are supported on the preferred AutoModel path.
- The Hugging Face fallback is narrower: text, flash-attention, and packing, without the native TP/EP/CP path.

### Asynchrony and correctness

Generation can overlap training. That improves utilization but creates stale or partially stale rollouts. Molt addresses this with:

- rollout-time token log probabilities;
- train/rollout importance ratios at token, sequence, or geometric-mean granularity;
- mask, clip, or upper-tail truncation modes;
- per-action stale-prefix masking for partial rollouts;
- strict force-sync mode when true on-policy behavior matters more than overlap;
- vLLM-to-training KL and filter-ratio metrics;
- MoE router replay and optional router freezing.

These mechanisms are technically meaningful, but they add algorithmic and operational complexity. A run can produce zero policy gradient if correction filters reject nearly every sequence; Molt logs a warning but experiment monitoring must treat this as a failed update.

## Supported learning methods

- REINFORCE / REINFORCE++-style returns;
- group-mean baseline;
- RLOO;
- GRPO;
- Dr.GRPO;
- PPO with GAE and critic;
- on-policy reverse-KL distillation;
- optional KL loss/reference model;
- dynamic reward filtering;
- rollout dump and replay.

Arbitrary Python can compute reward, including graders, tools, multimodal environments, and LLM-as-judge calls. This flexibility is also a security and evaluation-integrity boundary: reward code is trusted executable code and should be versioned independently from the policy being trained.

## Useful patterns for the ecosystem

1. Typed `Result` and token-exact `Trajectory` contracts.
2. Explicit `terminated` versus `truncated` outcomes.
3. Immutable action ranges and masks separating model actions from observations/tool output.
4. Stable `group_id` and `rollout_id` for multi-sample and multi-segment attribution.
5. Context-compaction detection that seals one trajectory segment and starts another.
6. Queue capacity as a declared resource and backpressure control.
7. Separate measurements for generator-idle and trainer-idle time.
8. Rollout dump/replay for deterministic training-path debugging.
9. Observable train/rollout mismatch instead of assuming API or kernel parity.
10. Independent promotion of a trained artifact only after evaluation.

These patterns may inform future ecosystem contracts, but this review does not promote Molt's internal dataclasses or CLI flags into canonical `.ai/` truth.

## Hardware and scope reality

The documented quick start is not a laptop workflow:

- Qwen3-4B assumes one server with eight GPUs split into four actor and four rollout GPUs.
- Qwen3.6-35B-A3B also assumes eight GPUs for the single-node smoke recipe.
- Qwen3.5-397B uses a documented 12-node/96-GPU topology.
- GLM-5.2 753B uses a documented 36-node/288-GPU topology.
- The project Dockerfile targets A100, H100/H200, and B200/GB200 stacks.

DGX Spark is not a declared quick-start target. A small compatibility experiment may be possible only after a dedicated probe of architecture support, model size, training precision, vLLM topology, memory, thermals, and kernel availability. No Spark compatibility claim is recorded.

## Evidence and maturity

- The first repository commit is dated 2026-06-23 and the first public release is dated 2026-07-14.
- The checked-out source reports version `0.1.2`, while the local Git tags are `v0.1` and `v0.1.1`; no `v0.1.2` tag was present at review time.
- The repository contains 19 unit-test files and 127 test functions.
- Static `compileall` for `molt`, `examples`, and `tests` passed.
- Bash syntax validation for all tracked shell scripts passed.
- Full unit tests were not run locally because the official CI path expects the large CUDA/GPU container.
- No public throughput, cost, convergence, or final-quality benchmark matrix was found in the README.
- The `~8.6K RL LOC` comparison uses the project's own import-graph methodology and different comparison dates; it is not an independent maintainability benchmark.
- “1T-class” is primarily an architecture/recipe claim. Release notes call Qwen3.5-397B verified end-to-end, while GLM-5.2 753B is ongoing scaling and its recipe identifies an untested memory boundary.
- The technical report is useful project evidence, not independent peer-reviewed production certification.

Current maturity classification: promising research alpha with substantial distributed-training engineering, not a production platform or stable ecosystem foundation.

## Security and supply-chain boundaries

1. **Python executor is not a security sandbox.** It uses `python -I`, a subprocess, timeout, memory cap, output truncation, and a temporary working directory, but does not isolate network or host filesystem access. Upstream explicitly says not to expose it to the internet.
2. **Loopback chat server has no authentication.** It binds to `127.0.0.1`; the unguessable session URL is effectively a capability token. Local processes remain inside the trust boundary.
3. **Remote model code executes.** Multiple loading paths use `trust_remote_code=True`; exact model/tokenizer revisions must be pinned and reviewed.
4. **Replay files are trusted inputs.** `torch.load(..., weights_only=False)` can execute pickle payloads. Replay directories must never accept untrusted artifacts.
5. **Agent and reward modules are executable code.** `--train.agent_path` dynamically imports a Python file.
6. **Prompts may leave the machine through logging.** W&B logging includes a generated sample and reward, not only scalar training metrics.
7. **Recommended prebuilt image is outside an NVIDIA registry.** README uses `hijkzzz/molt`; production experiments should build a reviewed image or pin a verified digest.
8. **Dependency reproduction is incomplete.** AutoModel and several GPU libraries are pinned, but many Python packages are not; `setup.py` names vLLM 0.24.0 while the Dockerfile installs 0.25.1 at this snapshot.
9. **Container hardening is insufficient.** Default execution is root; the optional local user is granted sudo and the entrypoint sets password `123`.
10. **Cluster networking is trusted.** Ray, vLLM router, engine control, model artifacts, datasets, and checkpoints need private network policy and broker-owned credentials.

## Correct ecosystem role

Molt should remain an optional isolated `Training/Evaluation Plane` adapter:

```text
canonical ecosystem contracts
→ versioned task + dataset references + immutable evaluator + budgets
→ isolated Molt experiment
→ checkpoint + metrics + trajectories + dependency/provenance bundle
→ independent evaluation gate
→ candidate model registry entry
→ explicit deployment approval
```

It must not receive authority from prompts or reward code, write directly to curated knowledge, publish a model automatically, or become a dependency of the embedded core.

## Promotion path

No activation is scheduled. If a concrete training use case appears:

1. Pin source, base image digest, dependencies, model, tokenizer, dataset, evaluator, and experiment configuration.
2. Build a hardened non-root container; remove the fixed password and direct secret access.
3. Run read-only hardware and kernel compatibility checks on the intended GPU target.
4. Replace example tool execution with a real sandbox and network allowlist.
5. Disable external telemetry by default or sanitize it through policy.
6. Start with a tiny deterministic SFT or RL smoke test and explicit resource budgets.
7. Record failed as well as successful trajectories and all stop reasons.
8. Compare against an unchanged baseline on a project-specific evaluation set.
9. Register only the artifact and evidence bundle; require a separate promotion decision.
10. Add rollback, uninstall, storage-retention, and incident procedures before recurring operation.

## Verdict

Molt is a strong reference for learning-loop engineering: token provenance, multi-turn action masking, asynchronous rollout/training coordination, mismatch correction, and distributed weight synchronization. It is not the vendor-neutral ecosystem itself. Preserve it as a specialized, replaceable research node for locally trainable open-weight policies.

## Sources

- [Upstream repository](https://github.com/NVIDIA-NeMo/labs-molt)
- [README and architecture](https://github.com/NVIDIA-NeMo/labs-molt#readme)
- [GitHub releases](https://github.com/NVIDIA-NeMo/labs-molt/releases)
- [Technical report DOI](https://doi.org/10.13140/RG.2.2.23375.65447)
- [Local loop contract](loops.md)
- [Current ecosystem architecture](architecture.md)
