# How to deploy a Cerebras-style Knowledge Base this week

**Author**: Christophe Pasquier 🇺🇦 ([@Christophepas](https://x.com/Christophepas))
**Date**: 2026-07-22
**Source**: https://x.com/Christophepas/status/2080018833784352826

---

![Cover](https://pbs.twimg.com/media/HN21raTWcAAAFsk.jpg)

Cerebras builds AI compute infrastructure and last week, their Knowledge Base got 2.4 million views on X.

Within 3 months of launching, Cerebras employees and AI agents were asking it 15,000 questions a day.

Within three months of launching, Cerebras employees, automations, and AI agents were asking it 15,000 questions a day.

This is a rare look inside a working company brain. It searches across Slack, GitHub, Google Docs, Jira, code repositories, and internal databases. It understands who can see what. It returns an answer with citations instead of a pile of links.

Every company wants that experience.

Very few should build the machinery Cerebras built to get it.

Over the last few years, we built Slite as that layer. A company can connect its tools and deploy an end to end, permission-aware company brain without turning internal search, context hoarding and management into a permanent engineering project.

### What Cerebras cracked - They disagreed with Karpathy and Garry Tan

Cerebras cracked one thing: it rejected the recent wisdom around Karpathy’s company brain and GBrain.

You do not need to turn company knowledge into a stored context graph. You can get perfect answers at runtime with intelligent retrieval.

For the past three months, everyone has been trying to build knowledge graph, replicating their data in github repos.

Cerebras built something simpler: enterprise search. That is it. Knowledge stays in the systems where it was created. When someone asks a question, Cerebras retrieves the relevant context from those sources at that moment.

There is no stored model of the company to sync. For knowledge that changes constantly, retrieving fresh context at question time is more practical than rebuilding yesterday’s context graph every night.

The graph starts becoming stale as soon as it is rebuilt, it's expensive to maintain, and most importantly - you don't need it for perfect search which is 99% of a company brain's application.

You need this. You can even build this, but you should not.

Cerebras proves an internal company brain can work. It also reveals the bill.

### Making company knowledge query-ready requires

continuous ingestion and source-specific refresh schedules

designing for each new source

ranking, reranking methods

authentication

### ACL replicas

### auditing, analytics

dedicated retrieval for each type of source

### ... among so many others

I can say so because I've spent the past two years building one of the best enterprise search out there with Slite.

Keeping every system reliable is extremely challenging work on which 3 of our engineers spend all their time.

For Cerebras, they have 700+ employees. They can afford to staff a team of 3-4 ppl for something as crucial as infra.

For most teams the math doesn't work.

You shouldn't build and maintain this, not when you can buy it.

### We productized what Cerebras built

For the past two years, we have built Slite Agent around the same insight as Cerebras:

Infer the right context when the question is asked instead of freezing company knowledge into a graph.

That meant building deep integrations with every source and doing the messy work behind permissions, syncing, retrieval, and reliability.

We also expose the same company brain through MCP, so your AI agents can ask questions and receive clean, permission-aware context.

What you get is:

A company brain that works today and will outperform anything you could build internally by Q4.

One source of trusted context for your employees and AI agents.

A team that handles permissions, infrastructure, security, and GDPR compliance for you.

You get the company brain Cerebras built without needing Cerebras-sized resources to build and maintain it.

### We went one step further

Even perfect retrieval can only return what your sources say. If a document is outdated or contradicted, search simply finds the wrong answer faster.

Slite Agent monitors your essential knowledge, flagging when it drifts from other signals in your team (a slack conversation, a new PR being merged, a support ticket) and proposes:

### the change to be applied

the reason and supporting sources

### a visible diff

A human approves or rejects every change. Nothing silently rewrites the company record.

### —

Company brains have become essential infrastructure pieces.

It's a necessity, not an engineering project.

Cerebras had to build it.

You probably should buy it.

![](https://pbs.twimg.com/media/HN21wO6X0AEPNyy.jpg)

![](https://pbs.twimg.com/media/HN2190jWQAAjPse.jpg)
