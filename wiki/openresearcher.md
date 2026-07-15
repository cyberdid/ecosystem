# OpenResearcher — upstream research node

**Updated:** 2026-07-15
**Status:** source downloaded; not installed, configured, trusted, or running

## Snapshot

| Field | Value |
|---|---|
| Upstream | [TIGER-AI-Lab/OpenResearcher](https://github.com/TIGER-AI-Lab/OpenResearcher) |
| Local path | `/home/snow/projects/OpenResearcher` |
| Branch | `main` |
| Commit | `785fd6ba5fcbc068daa4a2f07bbe0964f2983c86` |
| Commit date | 2026-06-10 |
| Downloaded | Source repository and full Git history, approximately 14 MB |
| Not downloaded | Model weights, training trajectories, offline corpus, embeddings, benchmark datasets |
| Ecosystem classification | External experimental reference node |

The checkout preserves its upstream `origin`. It is not a fork owned by this ecosystem and is not included in canonical `.ai/deployments.yaml` because no deployment exists yet.

## What it is

OpenResearcher is a research pipeline for synthesizing and evaluating long-horizon search trajectories:

```text
questions
→ one-time online evidence bootstrapping
→ fixed offline corpus and retriever
→ teacher search/open/find loop
→ versioned trajectories
→ supervised fine-tuning
→ benchmark evaluation
```

The released student model is a 30B-A3B MoE model trained for iterative web research. Its agent scaffold exposes three browser primitives: `search`, `open`, and `find`.

## Role in our ecosystem

OpenResearcher is not the ecosystem core and is not a replacement for the policy broker, LoopDefinition, audit ledger, sandbox, knowledge layer, or vendor-neutral model adapters.

Potential future uses:

- OpenAI-compatible local model deployment profile;
- experimental deep-research model adapter;
- reference implementation for `search/open/find` capabilities;
- long-horizon trajectory and experiment-ledger format study;
- offline retrieval/evaluation environment;
- BrowseComp-Plus, BrowseComp, GAIA, and xbench evaluation adapter.

Current policy:

```text
downloaded source
→ inspect and evaluate
→ no credentials
→ no services
→ no autonomous loop
→ no production claim
```

## Artifact inventory

| Artifact | Approximate remote size | Local status |
|---|---:|---|
| Git source | 14 MB checkout | Downloaded |
| OpenResearcher-30B-A3B BF16 model | 63.2 GB | Not downloaded |
| OpenResearcher trajectory dataset | 7.46 GB | Not downloaded |
| OpenResearcher corpus | 29.8 GB | Not downloaded |
| Retriever embeddings/indexes | Additional large artifacts | Not downloaded |

Artifact sizes are upstream snapshots and may change. Exact revisions and hashes must be recorded before any download or execution.

## Useful patterns to adopt

1. Separate corpus construction from repeated agent execution.
2. Keep research tools minimal and explicit: `search`, `open`, `find`.
3. Store complete successful and failed trajectories with provenance.
4. Evaluate retrieval success separately from reasoning and final-answer success.
5. Use fixed evaluation environments for repeatable experiments.
6. Treat turn budget as a measured parameter with diminishing returns, not as unlimited autonomy.

## Boundaries before execution

The upstream source is research code. Before it can become an ecosystem deployment, a dedicated integration must add:

- explicit code-license confirmation for the GitHub repository;
- pinned code, model, tokenizer, dataset, container, and dependency revisions;
- isolated Python/container environment;
- loopback/private binding instead of unauthenticated `0.0.0.0` services;
- credential broker ownership for Serper/OpenAI/Hugging Face secrets;
- network allowlist and untrusted-content boundary;
- typed tool arguments and capability policy;
- iteration, wall-time, token, GPU, thermal, storage, and cost budgets;
- structured completion and stop reasons;
- sanitized logging instead of raw reasoning/tool-result dumps;
- citation, source-quality, claim-support, and final-answer gates;
- project-specific evaluations and rollback/uninstall procedure.

`trust_remote_code` must not be enabled in a trusted deployment without pinning and reviewing the exact remote code revision.

## Known evidence limitations

- The paper is an arXiv v1 preprint, not a peer-reviewed production certification.
- Reported benchmark results are specific to the supplied model, retriever, scaffold, budget, and evaluator.
- The included evaluator focuses on short final-answer correctness and does not establish full report or citation quality.
- The GitHub checkout at the recorded commit has no root `LICENSE` or security policy, while separate Hugging Face model and dataset cards declare MIT.
- Offline retrieval improves reproducibility but freezes corpus freshness.
- Answer-guided corpus bootstrapping is useful for controlled synthesis but differs from open-world research where evidence coverage is unknown.

## Promotion path

No action is scheduled yet. If the node is activated later, use this order:

1. License and supply-chain review.
2. Read-only DGX compatibility probe with no credentials or network egress.
3. Model-only deployment behind the ecosystem adapter.
4. `search/open/find` capability adapter in a sandbox.
5. Small project-specific evaluation set.
6. Comparison with existing local and cloud deployments.
7. Promotion only if quality, safety, latency, resource use, and recovery gates pass.

## Sources

- [Upstream repository](https://github.com/TIGER-AI-Lab/OpenResearcher)
- [Paper: OpenResearcher](https://arxiv.org/abs/2603.20278)
- [Model card](https://huggingface.co/OpenResearcher/OpenResearcher-30B-A3B)
- [Trajectory dataset](https://huggingface.co/datasets/OpenResearcher/OpenResearcher-Dataset)
- [Offline corpus](https://huggingface.co/datasets/OpenResearcher/OpenResearcher-Corpus)
- [Loop engineering contract](loops.md)
- [Current architecture](architecture.md)
