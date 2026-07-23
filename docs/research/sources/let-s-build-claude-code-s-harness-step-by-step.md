# Let's build Claude Code's harness (step-by-step)

**Author**: Akshay 🚀 ([@akshay_pachaar](https://x.com/akshay_pachaar))
**Date**: 2026-07-15
**Source**: https://x.com/akshay_pachaar/status/2077455755066868098

---

![Cover](https://pbs.twimg.com/media/HNSTghtacAAQogV.jpg)

We will cover everything that goes into building a coding harness, the agent loop, planning, subagents, sandboxing, memory, and checkpointing, built step by step.

If you've ever tried building your own coding agent, you know how this goes. You wire a model up to file tools and a shell, point it at a real codebase, and it breaks down within a dozen tool calls.

It reads the wrong files, loses the goal halfway through, and fills its context with output it no longer needs.

Then the same task goes through Claude Code and finishes cleanly. The easy conclusion is that Anthropic simply has a better model, and that conclusion misses where the work actually happens.

The difference is the harness. A harness is the ordinary code wrapped around the model, and it handles planning, tool execution, memory, and safety while the model only decides the next step.

Here's what a fully harnessed agent looks like when you draw it out:

The picture looks busy, but it breaks into four groups:

Memory feeds the model its working context plus facts it has learned across sessions.

Skills encode how the agent should operate, meaning the procedures, constraints, and heuristics it follows.

Protocols connect the agent to users, tools, and other agents.

The harness core ties it all together with sub-agent orchestration, a sandbox, an evaluator, an approval loop, observability, and context compression.

Anthropic describes this split as the brain and the hands. The model is the brain that picks each action, and the harness is the hands that carry it out and keep the run on track.

So the gap between your agent and Claude Code isn't the model, it's the machinery around the model.

Claude Code is one of the most capable harnesses in production today, and it's built from a surprisingly small set of the layers in that illustration. To see how much of that machinery you'd have to build yourself, I rebuilt it in CrewAI, an open-source framework for orchestrating agents.

More of it maps onto built-in features than I expected, and the part that doesn't is where the real engineering lives.

Let's build it layer by layer, starting with the core loop and stacking planning, subagents, sandboxing, and memory on top. At each step we'll mark where the framework ends and where your job begins.

### How Claude Code's harness works

At the center of Claude Code is a plain agent loop. You send it a message, the model decides what to do next, and it either responds directly or requests a tool. If it requests one, the tool runs, the result goes back into the conversation, and the model decides again.

This repeats until the model returns a final answer with no further tool calls.

Inside that loop, the model reads files, edits code, runs shell commands, and executes tests. These aren't separate modes. They're just different tool calls inside the same loop.

The loop alone isn't enough for a reliable coding agent, though. Claude Code adds planning, file tools, subagents, memory, and a permission and sandbox system around it. These layers don't replace the loop, they make it safe and reliable enough for real work.

That's the architecture we'll rebuild, the core loop first, then each layer on top, mapping every layer to the CrewAI feature that handles it.

### The core agent loop

The loop runs the same sequence until the task is done:

Ask the model to perform the task.

The model responds directly or requests one or more tools.

If tools are requested, run them and return the results to the model.

Repeat with the updated conversation.

When the model responds without requesting any tools, the task is complete.

Each tool call completes one step, gives the model new information, and feeds into the next decision. A simple question might finish in one iteration, while fixing a complex bug or refactoring a large codebase can take dozens of iterations before the model has enough to produce a final answer.

CrewAI provides this execution loop automatically as soon as you create an agent. You don't implement the while loop yourself, you define the agent and assign it a task.

### Building the first agent

Let's create a simple Bug Fixer agent.

Three concepts to understand here:

An Agent defines who does the work, through its role, goal, LLM, and tools.

A Task describes the assignment.

A Crew brings agents and tasks together. Calling kickoff() runs the same execution loop described above, regardless of whether the underlying model is Anthropic, OpenAI, Google, or something else.

### Giving the agent tools

Tools are what let a model that only generates text actually work on a codebase. They read files, write them, run shell commands, and call external APIs.

CrewAI ships file system tools out of the box:

FileReadTool reads files.

DirectoryReadTool lists directories.

FileWriterTool writes files.

These also double as external memory. Instead of holding a large search result in the model's context window, the agent can write it to a file, keep only the filename, and read it back when needed.

This keeps the context window smaller and the model more focused, which is what Anthropic calls context engineering.

Built-in tools cover common workflows only. For anything more specific, you expose a Python function as a tool with the @tool decorator.

The docstring acts as the instruction manual, telling the model what the tool does, when to use it, and what it expects as input.

### Planning long-running tasks

As tasks get more complex, a plain execution loop starts losing track of the original goal. After enough tool calls, file reads, and intermediate results, the context fills up and the objective gets crowded out by everything that came after it.

This slow degradation is what people call context rot.

Planning addresses it directly. The agent builds a step-by-step plan before doing any work and keeps that plan in context throughout execution.

The plan doesn't do the work. It's a roadmap that keeps the model connected to the original goal, which is the same job Claude Code's to-do list does.

CrewAI adds this at the crew level with planning=True. It generates a plan before execution and keeps it available as the task progresses.

Note: By default, CrewAI uses gpt-4o-mini for planning, and you can swap in any LLM you prefer for that step.

Individual agents can also reason about their own work with reasoning=True:

Planning and reasoning solve different problems. Planning builds a high-level roadmap for the overall task, while reasoning gives one agent time to think through its own approach before acting.

When reasoning is enabled, the agent:

Reflects on the task and drafts an execution plan.

Evaluates whether the plan is ready.

Refines the plan if necessary, until it's satisfied or hits max_reasoning_attempts.

Injects the finalized reasoning plan into the task before execution.

Together, they keep the agent anchored on long-running tasks and reduce drift from the original goal.

### Delegating with subagents

Planning keeps the agent focused, but it doesn't reduce how much information the model has to hold. On a large codebase, even a well-planned task can exceed a single context window.

Finding one bug may require reading dozens of files, and the main agent doesn't need to keep all of them in memory.

Subagents solve this through delegation. The main agent hands a specific task to a helper agent, which works in its own context and returns a short summary. The main agent sees the conclusion, not the intermediate steps.

CrewAI supports this through hierarchical workflows, where a manager agent delegates to specialist agents and combines their results.

In our earlier setup, one Bug Fixer agent did all the heavy lifting. Let's split the work across a manager and three specialists:

Codebase Explorer explores the code and maps the repository.

Software Engineer implements the requested change.

Test Runner runs the tests in the sandbox and reports pass or fail.

Engineering Lead oversees the three specialists.

One thing to note is that allow_delegation is disabled by default, so it must be explicitly enabled on the manager.

### Sandboxing: Securing agent execution

An agent with shell access can run a destructive command, and telling the model not to do something isn't a safeguard.

Real protection comes from two layers:

A permission system that requires approval for sensitive actions.

A sandbox that isolates execution, so even approved commands can't touch the host machine.

Anthropic uses the same approach. Moving code execution into a sandbox cuts down how often a user needs to approve actions while still protecting the host system.

### Sandboxing in CrewAI

Executing code inside a sandbox rather than on the host machine applies that second layer. In this setup, code runs inside E2B, which spins up a fresh VM per session and destroys it afterward.

Shell commands and Python run entirely inside that isolated environment.

### Human-in-the-loop approval

Setting human_input=True on a Task pauses the crew after it generates an answer. You review the output, then approve it or send it back for another iteration.

When execution reaches that task, CrewAI waits for your feedback through standard input.

If your crew runs behind a web app or chat interface rather than a terminal, CrewAI's webhook-based human-in-the-loop system handles the same review step.

### Memory and checkpointing

By default, an agent forgets everything once a run ends. Come back tomorrow to fix another bug in the same project, and it starts from zero.

Two mechanisms let an agent carry information across runs, and each serves a different purpose:

Checkpointing saves the agent's state during a run, so it can resume after an interruption or continue from the same point along a different path.

Persistent memory stores facts across separate conversations, including project preferences like "always format the final code before finishing."

### Memory in CrewAI

CrewAI provides a unified Memory interface rather than separate short-term, long-term, entity, and external memory types. When saving, it uses an LLM to identify important details, organize them, and make them retrievable later.

Setting memory=True on the crew gives it memory across runs. After each task, CrewAI extracts useful facts from the output and stores them, and in future runs it retrieves relevant memories and adds them to the task prompt.

All agents in a crew share its memory unless an agent is given its own.

### Checkpointing in CrewAI

A checkpoint is a snapshot of an agent's progress, including its configuration, task state, memory, intermediate results, inputs, and execution history.

By default, CrewAI creates a checkpoint whenever a task finishes, allowing the workflow to resume from that point if it's interrupted.

Checkpoints can live in one of two built-in stores:

JsonProvider saves each checkpoint as a separate JSON file, which is easy to read and inspect manually.

SqliteProvider stores all checkpoints in a single SQLite database, which holds up better under frequent checkpointing and larger workloads.

Crew, Flow, and Agent all accept a checkpoint argument, and children inherit from their parent unless they set their own value.

### Putting it all together

Here's the full harness on one task, with the execution loop, tools, planning, subagents, sandboxing, and memory working together:

Agent harnesses are easiest to evaluate when success can be checked automatically. A test suite gives the agent a concrete objective, so it can plan, edit, test, and repeat until everything passes.

So this was tested against a small codebase, a BankAccount class with two real bugs and five tests, three of which failed. The rule was to fix only the implementation, not the tests.

This mirrors how Anthropic evaluates coding agents internally. One published example has Claude rebuilding a clone of the claude.ai interface against a large suite of failing tests.

Here, the harness took the project from 3 failing and 2 passing to all 5 passing, with the implementation-only rule closing off the shortcut of editing or removing the failing tests.

### What's still your job

Some parts of the system aren't things the framework builds for you:

The prompts. Each agent's behavior comes from its role, goal, and backstory. Getting those right takes testing and iteration, and no configuration flag substitutes for it.

The execution environment. The sandbox, whether E2B or a self-managed VM, has to be set up and wired in.

Tool selection. Which tools each agent gets, and which agent should have access to what, is a design decision the framework doesn't make.

There's also a cost to the harness itself. Planning, subagents, and looping all add API calls, so a complex agent setup can end up more expensive than a task a single model call would have solved directly.

And there's a longer-term limitation worth keeping in mind. As models improve, some of the scaffolding stops being necessary, because some of what gets built into a harness today is a workaround for today's model limits rather than a permanent requirement.

Anthropic originally used context resets to keep Claude Sonnet 4.5 from ending tasks too early, and they weren't needed anymore with the more capable Claude Opus 4.5.

### Wrapping up

That's the whole finding. A coding agent's capability lives mostly in the harness, and an orchestration framework hands you more of that harness than you'd guess.

The loop, planning, delegation, sandboxing, and memory all arrive as configuration, while the prompts, the execution environment, and the tool choices remain yours.

If you want to run this against your own codebase, the CrewAI docs cover every feature used here, and the framework is fully open source.

### Check out CrewAI Docs →

Find all the code here →

Thanks for reading!

Cheers! :)

![](https://pbs.twimg.com/media/HNMVomkbcAAGua3.jpg)

![](https://pbs.twimg.com/media/HNMRlqPbQAA8292.jpg)

![](https://pbs.twimg.com/media/HNMSVOOaMAA_7U-.jpg)

![](https://pbs.twimg.com/media/HNMUERcbAAAxOdL.jpg)

![](https://pbs.twimg.com/media/HNMRqe0bIAAhw91.jpg)

![](https://pbs.twimg.com/media/HNMTw28a0AAOB4K.jpg)

![](https://pbs.twimg.com/media/HNMP83cbMAAoIqL.jpg)

![](https://pbs.twimg.com/media/HNMSztJaIAExDf3.jpg)

![](https://pbs.twimg.com/media/HNMLQW5bUAAz989.jpg)

![](https://pbs.twimg.com/media/HNMVeICbgAA0qaB.jpg)

![](https://pbs.twimg.com/media/HNMM_tdagAEOR7w.jpg)

![](https://pbs.twimg.com/media/HNMSjrvbEAENJn3.jpg)

![](https://pbs.twimg.com/media/HNMTaRJbEAAci7X.jpg)

![](https://pbs.twimg.com/media/HNMPWOVbgAAqBEl.jpg)

![](https://pbs.twimg.com/tweet_video_thumb/HNL--RXbYAA1My-.jpg)
