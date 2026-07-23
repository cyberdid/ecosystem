# LangChain’s Open-Source Software Factory

**Author**: Brace ([@BraceSproul](https://x.com/BraceSproul))
**Date**: 2026-07-18
**Source**: https://x.com/BraceSproul/status/2078558852921094253

---

![Cover](https://pbs.twimg.com/media/HNiF6CFbAAAB3Ua.jpg)

At LangChain, we interact with software engineering agents from the terminal, Slack, Linear, GitHub, and CI.

Different workflows need different agents. Local coding should feel interactive. Cloud coding should run in the background and open PRs. Code review should be careful and tied into GitHub. Repo documentation should stay close to the code and give agents useful context.

We’ve built that system as a set of open-source tools:

### dcode for local coding

### OpenSWE for cloud coding agents

### OpenSWE Review for automated code review

### OpenWiki for repo documentation and agent memory

Together, they form our software engineering agent factory. This is the shape we use internally: local agents, cloud agents, review agents, repo memory, open models, and LangSmith traces across the system.

### Why open source matters

Software engineering agents read code, edit code, review PRs, and participate in engineering workflows. Teams need to understand and control how those agents behave.

That is hard if the agent is a closed system. You are limited to the provider’s supported models, review behavior, integrations, and observability.

We want agents that teams can inspect, modify, and adapt to their own workflows, including their own review standards, repo conventions, model choices, and internal tools. That is why these projects are open source.

The pieces

### dcode

dcode is the local coding agent we use from the terminal.

The CLI and agent runtime run locally on your machine, while the model can still be hosted. That lets developers work directly against a local repo while using large coding models that may not run on a laptop.

We use dcode for interactive coding work: exploring a repo, making edits, and running implementation tasks from the terminal.

### OpenSWE

OpenSWE is the cloud coding agent we use when work should happen in the background.

A lot of engineering work starts outside the terminal. A bug comes up in Slack. A feature request lives in Linear. A repo maintenance task needs to run on a schedule.

OpenSWE can be triggered from Slack, Linear, GitHub, or the web UI. It runs in the cloud, works on the code, and can open a pull request when it is done.

Internally, this has become one of our most-used agent workflows. In just the last week, we triggered OpenSWE almost 1,000 times from Slack alone, not including Linear or UI usage.

Because OpenSWE runs in a sandbox in the cloud, we can run many coding agents in parallel without tying up anyone’s local environment.

OpenSWE also includes a UI for inspecting agent work, chatting with the cloud coding agent, configuring models and prompts, viewing analytics, and setting up scheduled automations.

### OpenSWE Review

OpenSWE Review connects to GitHub and automatically reviews pull requests. It identifies bugs and regressions before code merges.

It also performs extremely well on external benchmarks. On the Offline Code Review Benchmark, OpenSWE Review scores 47% when running GPT-5.5 with medium reasoning. That places it #6 overall and #1 among open-source code review agents.

Code review is highly organization-specific. Teams differ in what issues they care about, how they phrase comments, and when they want an agent to block, suggest, or stay quiet.

OpenSWE Review gives us a strong default that we can adapt by changing prompts, workflows, model choices, and repo-specific behavior.

### OpenWiki

OpenWiki generates and maintains codebase documentation using Google’s Open Knowledge Format.

The docs live with the code and are kept up to date automatically via a GitHub action. That gives both humans and agents a maintained knowledge layer for the repo, without needing to worry about maintaining the docs (OpenWiki does that for you!).

If an agent has to rediscover the architecture of a repo every time it runs, it wastes tokens and misses important conventions. OpenWiki gives coding and review agents a better starting point, while supporting an auto-update flow so you never need to think about maintaining your agent docs again.

### The stack

### Deep Agents

dcode, OpenSWE, OpenSWE Review, and OpenWiki are all built on Deep Agents.

The workflows are different, but they share the same underlying agent foundation. That gives us a consistent way to build, customize, and improve agents across local coding, cloud coding, review, and documentation. Sharing code, resources and engineering know-how is made even easier when they’re all built in the same framework.

### Open models

We’ve optimized the stack for open models.

SWE agents get expensive quickly when they run across an organization. Local coding, cloud coding, code review, documentation, scheduled maintenance, and repeated repo analysis all use tokens.

Open models give us more control over cost (the key reason), latency, and deployment choices. They also let teams route different tasks to different models, experiment with open coding models, or even fine-tune models for their own repos and workflows.

### LangSmith

We trace these agents with LangSmith.

When an agent opens a PR, leaves a review comment, or fails on a task, traces show the files it inspected, the context it loaded, the tool calls it made, and where it got stuck.

Those traces help us debug individual runs and improve the system over time. We use them to identify failure modes, improve prompts, compare models, and feed higher-quality examples into continual improvement workflows with LangSmith Engine.

Engine for coding agents is a new workflow we’ve been experimenting with, where we have Engine run over coding agent traces, identify shortfalls, and propose optimizations. Since every coding agent run from every employee at LangChain is traced, Engine is able to do identify and preform these optimizations from birds eye view, instead of individually on specific engineers traces.

### Build your own software engineering agent factory

This stack reflects how we use software engineering agents at LangChain, but the pieces are open source so other teams can adapt them, and retain full control over your own software factory.

You can start small:

Use dcode for local coding.

Add OpenSWE to run coding agents from Slack, Linear, GitHub, or the web UI.

Turn on OpenSWE Review for automated PR review.

Use OpenWiki to maintain repo knowledge for humans and agents.

Connect traces to LangSmith if you want observability and improvement loops across the system.

The goal is not to move every engineering workflow into one agent interface. It is to put the right agents in the places where engineering work already happens, with enough control to make them fit your repos, models, and team conventions.

![](https://pbs.twimg.com/media/HNiF_OLawAEXGzE.jpg)

![](https://pbs.twimg.com/media/HNiGBbAakAAv1rp.jpg)

![](https://pbs.twimg.com/media/HNiGC9hb0AAXW9M.jpg)

![](https://pbs.twimg.com/media/HNiGFO0bsAAi7hW.jpg)
