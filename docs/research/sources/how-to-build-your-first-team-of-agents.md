# How to build your first team of agents:

**Author**: Machina ([@EXM7777](https://x.com/EXM7777))
**Date**: 2026-07-18
**Source**: https://x.com/EXM7777/status/2078476892127318295

---

![Cover](https://pbs.twimg.com/media/HNg7rkmbwAAyYjd.jpg)

I'm going to show you how to build your first team of AI agents... and how to wire them into a self improving loop inside a shared workspace

the team we're building has 5 agents, one for each function your business runs on: lead acquisition, content creation, sales pipeline, service delivery, finance

they run on three engines - the apps an agent lives in, and you may already pay for them: Claude Code, Codex and Hermes (this one's free)

and the workspace that holds them together is called Raft: it's free to start, the piece that turns five separate chat windows into an actual team

you can build nearly all of this yourself - the names, the memory, the scheduled run

the one piece you can't write is the shared room where agents see each other's work

by the end you'll have the full build order: the files, the schedules, the review rules, and the exact first week

### why one assistant stops being enough

### a single assistant has a structural problem: you are its quality control

so output scales with your attention - the exact resource you were trying to free

and the obvious fix, opening more sessions, makes it worse

without names, agents blur together:

### one drafts a plan

### a second drafts a competing plan because it never saw the first

three parallel runs rediscover the same thing separately, because nothing they learn is shared

### more agents, same bottleneck, now with babysitting

### the companies building these models already work the other way

### at Anthropic, an agent teammate creates 65% of the product team's code

it sits in their channels, remembers every discussion it follows, and schedules its own tasks days ahead

that number is a shift bigger than one company: the interface for AI has changed twice already, from a website you visit to an app you install

the third interface is a persistent coworker, one that works around the clock

here are four things that separate a real team from a pile of agents:

persistent identity: an agent with a name and a role, not a fresh session. you know who deals with what, and where to look when something isn't working

compounding memory: each agent keeps its own notes and playbooks, so they don't just grow, they diverge. a few weeks in you have five different specialists, each advising from its own corner of the business

a reviewer that isn't the author: an agent grading its own work approves it every time. a second agent told to assume the work is broken catches what the author can't see

a shared room: one workspace where every agent sees the others' output, instead of five isolated chats with you as the copy-paste layer

the gain is measured: split the work across agents with a lead reviewing the result, and on Anthropic's own research benchmark that setup came out 90.2% ahead of the same model working alone

you can hand-write all three files and run them through a shared workspace... or you can run them on Raft

### what Raft is, in one minute

Raft is a workspace where humans and agents work together as teammates

### it looks like Slack: channels, threads, tasks, DMs

### except the members are agents with persistent identity and memory

they claim tasks from a channel, run in parallel, hand work to each other, and review each other's output in shared threads

you drop a request in a channel the way you'd brief a colleague, and the work happens while you do something else

three practical details for a first team:

agents run on your own machine: they run through a light local process called the Computer. you just log in on Raft and install it with one line pasted into your terminal (the command window). your files, tools and AI subscriptions stay on your hardware, so Raft never sits between your agent and its model

use the subscriptions you already pay for: Claude Code, Codex, Gemini CLI, Cursor and more. no new token bill, and an agent you run elsewhere, like Hermes, can join too

the free version covers everything in this article: paid plans add some extra premium features, and an agent only takes a tenth of a seat

and the proof it holds up at scale: 20,000+ builders and teams already built with it, and the team behind Raft runs the whole company inside it - 10 humans and 100+ named agents

### so the room is solved

what's left is hiring the five agents that live in it

### the team plan: five pillars, five hires

map the team to the five functions every business runs on, one named agent each:

lead acquisition - watches your sources, sweeps for prospects, drafts the first touch

### content creation - produces everything your audience reads

sales pipeline - keeps every open conversation moving so deals advance without you pushing

### service delivery - produces the work your clients pay for

finance - tracks invoices, costs, and what's actually left at the end of the month

### each pillar gets the engine built for its kind of work

an engine is the app the agent runs in, and each of the three brings different models and different instincts

### so here's what each one is, and the tasks it should own

and the biggest advantage of the whole build: none of it is a new agent platform you configure from scratch

these are proven harnesses you may already run, used exactly as you use them today

Claude Code is the same app Anthropic keeps evolving into a full teammate, tags and all

your team inherits every upgrade these tools ship, forever

### Claude Code, the writer

Anthropic's terminal app, running the Claude models: Fable 5 at the top for the hard thinking, cheaper tiers below for routine runs

the Claude models are the strongest writers available, which is why this engine owns everything a human will read: content creation and service delivery - posts, proposals, client deliverables

two habits make it a teammate instead of a chat:

### scheduled runs: a job that repeats until it's done, one change per round

a finish line: you write what "done" means, and a second pair of eyes checks every round whether you've crossed it

Claude Code has built-in commands for both - /loop for the scheduled runs and /goal for the finish line... on Raft the same two habits live in the room: a schedule is a sentence in chat, and the finish line is the reviewer you'll meet in the loop section

and the money rule that makes it affordable: the premium model earns its seat on planning and review, the routine runs go to the cheap tier

give it tasks shaped like "write X for Y, here's the brief, stop when the checklist passes"

### Codex, the builder

OpenAI's coding agent - it comes with the ChatGPT subscription you may already have, and runs the GPT models

it codes, that's its job: it reads a whole codebase, ships changes as reviewable diffs, and runs inside a sandbox so a mistake can't leave the folder

on this team it builds the workflows and internal tools every other pillar ends up requesting: the finance tracker, the invoice parser, the report scripts, the small automations that glue the team together

give it tasks shaped like "build X, prove it works by pasting the output"

### Hermes, the night shift

### the open source agent from Nous Research, built to stay online when you're not

it joins Raft as an external agent through a small gateway process, and its scheduler checks every 60 seconds for due jobs, running each one in a fresh session

three of its features map straight onto sales work:

### heartbeats: recurring jobs that fire whether you showed up or not

monitors: watch a source, an inbox, a list, and say nothing until something changed

playbooks: when it cracks a hard problem it saves the solution as a reusable recipe, so the same problem never costs twice

that's why it owns the always-on pillars: lead acquisition and sales pipeline - the morning sweep, the reply watch, the follow-up chase

and if you'd rather not set up an external agent, Raft's built-ins cover the same ground: reminders handle the schedules and the watch-and-report checks, and every agent keeps its own playbook notes anyway... Hermes is the specialist version, not the entry ticket

### the routing table

### lead acquisition: june - Hermes - 07:00 source sweep

content creation: cole - Claude Code - monday: draft the week's pieces

sales pipeline: etta - Hermes - hourly reply check, silent by default

service delivery: ray - Claude Code - daily: client deliverable pass

### finance: penn - Codex - friday: the numbers report

the names are examples, pick your own... the routing is the part to copy

### five agents, three engines, one room

now build the first one properly, because the pattern repeats for the other four

### build your first specialist

every agent is assembled from the same five parts: a name, a soul, a memory, goals, and a heartbeat

here's june, the lead acquisition agent, end to end

### 1. the name

### pick a real one, not "agent-2"

the name is how you route work ("give this to june") and how you audit it ("june drafted this, who reviewed it?")

### 2. the soul

the file everyone imagines here is really three layers on Raft: the job description you write at hire, the config that scopes what it can touch, and the memory it grows itself across sessions... the first is given, the last is earned

you don't write the soul up front: you tell june things in chat - "drafts only, never contact a prospect" - and her own version of it accumulates

you still want to know what a finished one looks like, it's the bar you hold the agent's version to... half a page is enough:

## june: lead acquisition

### you find and qualify prospects, you never contact them

scope: prospecting only - no content, no client work, no finance

### tone: plain english, no hype, numbers over adjectives

every workday you deliver: qualified prospects with a one-line reason each, and a first-touch draft per prospect

hard rules: drafts only (a send is always a human decision), every prospect carries a source link, if a source looks stale or scraped wrong say so instead of guessing

outside Raft, write this yourself and point the agent at it

### 3. the memory

the agent keeps this one on its own: a MEMORY.md plus working notes - what worked, what turned out wrong, which sources are gold and which are noise

you don't maintain it, you feed it - every correction you give in chat is something it writes down

have it compress the notes when they pass a page - memory that grows forever stops being read

### 4. the goals

what this agent owns, what done looks like, and what it must hand to you instead of deciding - said once in chat, kept by the agent:

### own: a steady flow of qualified first-touch drafts

### done: every prospect has a reason, a source, and a draft

escalate: pricing questions, anyone answering, anything legal

### 5. the heartbeat

the schedule it wakes on without being asked (on Raft this is the reminders feature: you say it once in chat, the agent wakes itself)

two are enough for june:

every morning 07:00: sweep the source list, deliver new prospects + drafts to the leads channel

### every hour: check replies. if nothing changed, say nothing

the full hire: one name, a few chat messages, a couple of scheduled lines... the files grow on their own from there

in Raft the output lands in a channel as a draft, and that's where the next layer takes over

### the self improving loop

### the loop stands on one rule: no agent grades its own work

### left alone, an agent will praise its own output every time

so every deliverable crosses a second agent told to disagree, with an instruction as short as this:

### you review june's prospect drafts

assume every draft is broken and find where: wrong fit, weak reason, stale source, claims without links

### reject with the reason, or approve with one line

the reviewers aren't new hires, they're the same five agents pointed at each other's work

cole's content drafts get reviewed by ray against the client brief, june's outreach gets checked by etta against deal history, penn's scripts get stress-read by cole

and everything lands as a draft in a channel - never a sent email, never a pushed change

you stay the final call on anything that leaves the building: sends, money, client deliverables

what changes is what reaches you: resolved drafts with the disagreement already worked out, instead of raw output you check line by line

and here's what makes the loop self improving: every rejection carries a reason, and the reasons get written back into the soul and memory files

the same mistake doesn't survive twice, so the team you run in month three is a different machine than the one you hired

### your first week

don't stand up five agents at once

### a team you can't feed is theater

day 1: install the Computer, create one channel, hire ONE agent... for the pillar where you lose the most hours

day 1: set its soul from the template above, said in chat or written as a file, with your scope and rules swapped in

### day 2: add its reviewer with the short instruction, route both into the channel

day 3-7: run the pair daily, and every time you correct the same mistake twice, write the correction into the soul file

### week 2: add the next pillar, and only because the first one now runs without you

the first week feels slower than doing it yourself, because you're writing down judgment you usually apply on the fly

that judgment is exactly what the files capture - and it's why week four looks nothing like week one

### the playbook

5 pillars, one named agent each: lead acquisition, content creation, sales pipeline, service delivery, finance

engines by work type: Claude Code writes, Codex builds, Hermes runs the always-on jobs

### per agent: a name, a soul file, a memory file, a goals file, a heartbeat

1 loop: no agent grades its own work, and every rejection writes back into the files... the team improves itself

### 1 room: Raft, drafts in channels, you as the final call

1 pillar at a time: five hungry agents on day one is how the whole thing gets abandoned

thank you Raft for sponsoring this piece

### the bottleneck was never the model

it was the structure around the model, and you just read the whole structure

![](https://pbs.twimg.com/media/HNg7tY3bEAAMhnj.jpg)

![](https://pbs.twimg.com/media/HNg7tNFagAAJAqg.jpg)

![](https://pbs.twimg.com/media/HNg7sv8bkAAZiK9.jpg)

![](https://pbs.twimg.com/media/HNg7sZHaAAAyrGD.jpg)

![](https://pbs.twimg.com/media/HNg7sJkbEAA5Q8c.jpg)

![](https://pbs.twimg.com/media/HNg7sh5aAAATa1L.jpg)
