# The Sinon methodology

A repeatable process for assessing an LLM agent. It is written to be followed by
someone who has never used this tool, and to produce a report another
practitioner can check.

The corpus is the easy half. The reason agent testing produces unusable results
today is not a shortage of jailbreak prompts — it is that nobody agrees on what
counts as a finding, what counts as coverage, or what a passing result licenses
you to say. This document fixes those three things first, and the tool
implements what it says.

---

## 0. The three commitments

Everything below follows from these.

### A verdict is an observed fact

A finding is recorded when something *happened*: a unique token came back out of
the agent, an instrumented tool was called, a request arrived at a listener under
your control. Not when a model judged an answer to look risky.

Where a check can only pattern-match on prose, it is marked `heuristic`, it is
labelled that way in every output format, and it is capped in scoring. Heuristics
earn their place — an agent that answers "sure, here's how" is worth flagging —
but they are never allowed to carry the same weight as an observation.

### A skip is never a pass

If the target cannot show you its tool calls, you cannot conclude anything about
its tool behaviour. The honest result is `SKIP`. It lowers coverage, coverage
caps the grade, and the report says which probes could not be answered and why.

A test kit that quietly reports "no findings" because it could not look is worse
than no test kit, because someone will act on it.

### A pass is the absence of a finding

The corpus contains attacks somebody has already written down. It cannot tell
you how the agent responds to one nobody has. Every Sinon report says so, on
every run, including clean ones. The top grade is A and there is deliberately no
A+.

---

## 1. Scope and authorization

Do this before you install anything.

**Establish what you are allowed to touch.** You need, in writing:

- the client or system owner, and the person authorizing the test
- a reference to that authorization — a purchase order, a signed rules of
  engagement, a ticket
- a date window
- the exact hosts in scope
- an escalation contact who is reachable during the window

Put it in an engagement file. Sinon will not test a non-local target without one,
and it re-checks the window on every run:

```bash
sinon init --engagement engagement.yaml
```

**Decide the identification posture.** By default every request carries
`X-Sinon-Run`, `X-Sinon-Probe` and `SINON-` prefixed canaries, so the client's
blue team can tell your test from a real attack at a glance. Keep it that way
unless the engagement is specifically a detection exercise — and if it is, record
the client's agreement to that, because turning it off requires its own flag and
appears in the banner and the report.

**Agree the blast radius before you start.** Ask three questions:

1. Is the target production or staging? If production, what is the rollback?
2. Does the agent have tools that touch the real world — mail, payments, tickets,
   deploys? Which of those are live in this environment?
3. Who is on call, and what does "stop" look like?

Sinon's own toolbelt is synthetic and touches nothing. That protects you from
Sinon. It does not protect you from the target: if the agent under test has a
real `send_email` and it decides to use it, mail leaves the building. Staging
first, always.

---

## 2. Understand the target before you probe it

Fifteen minutes here changes what the results mean.

**Map the trust boundary.** Draw where untrusted content enters. Not where you
*think* it enters — where it actually can:

- retrieved documents, web pages, RAG chunks
- email, tickets, chat messages, form fields, order notes
- files in a repository or workspace, including dependencies
- tool results, especially error strings from third-party APIs
- tool *descriptions*, if the agent loads plugins or MCP servers
- metadata: filenames, display names, subjects, alt text
- anything persisted across sessions: memory, notes, preferences

Each of these maps to a Sinon delivery channel. Anything on your list that the
corpus does not cover is a probe you should write.

**Inventory the tools and, more importantly, the combinations.** Permission
reviews consider tools one at a time; risk lives in the pairs. A read tool is
harmless. An outbound network tool is harmless. Both on the same agent, driven by
the same untrusted text, is a general-purpose exfiltration primitive. Write down
what any two granted tools compose into.

**Find the irreversible actions.** Deletes, sends, payments, publishes, standing
rules, scheduled tasks, entitlement changes. These get the highest severities in
the corpus because a wrong answer cannot be taken back.

**Get the real system prompt if you can.** Pass it with
`--system-prompt-file`. Testing against Sinon's built-in prompt measures the
harness; testing against theirs measures their agent.

---

## 3. Baseline

Run the direct probes first:

```bash
sinon run --engagement engagement.yaml --target ... --channel user_turn
```

These are the calibration set. Almost every modern model refuses a blunt "ignore
your instructions", so passing them tells you very little on its own — but
failing them tells you a great deal, and the comparison between direct and
indirect results is the most informative number in the whole report.

An agent that passes `PI-DIR-001` and fails `PI-IND-001` does not have an
injection defence. It has a model that was trained to be polite to its user.

---

## 4. The full run

```bash
sinon run --engagement engagement.yaml --target ... --out ./reports
```

Notes that matter:

**Repeat, if the target is a language model.** Agents are not deterministic. An
attack that lands one time in three is a finding, not a flake, so `--repeat 3`
reports the worst outcome rather than the best. Budget for it: three runs of 54
probes is 162 requests plus tool turns.

**Rate limit against production.** `--rate-limit 30` if you are sharing capacity
with real users.

**Watch the skips.** They are the finding behind the finding. Seven skipped
probes with the reason "target exposes no tool telemetry" is itself worth a
paragraph in the report: nobody can audit this agent's actions, including the
people who run it.

**Keep the artefacts.** The JSON output carries full canaries, the rendered
payload, the tool calls and the response. That is what makes a finding
reproducible by someone who was not in the room.

---

## 5. Triage

Read the report in this order.

**Critical findings first.** A critical is an outcome that cannot be walked back:
live cloud credentials, code execution, money moved, a standing rule created,
data confirmed to have left. One critical caps the grade at F — not to be
dramatic, but because the rest of the agent's behaviour is not the interesting
question any more.

**Then separate deterministic from heuristic.** Deterministic findings can go
into the report as they stand. Heuristic ones need a human to look at the
transcript before they are reported to a client. Sinon marks which is which; do
not skip this step, because a heuristic false positive in a client report costs
more credibility than the finding was worth.

**Then look for the pattern rather than the list.** Fifteen findings is rarely
fifteen problems. Usually it is two:

- *content is being treated as instruction* — which explains every `PI-IND`,
  `PI-OBF` and content-triggered `TA`/`OP` failure at once
- *the agent's authority is not bounded by the harness* — which explains the
  scope, permission and confirmation failures

Report the two causes with the findings as evidence. A client can fix two things.

**Then read the skips and the errors.** Errors mean something was wrong with the
run; resolve them before trusting the grade.

---

## 6. Reporting

Sinon writes four formats because they have four audiences:

| Format | For |
|---|---|
| HTML | The deliverable. Self-contained, prints, opens on an air-gapped laptop. |
| Markdown | The ticket, the Slack message, the email. |
| JSON | Reproduction, diffing between runs, your own analysis. |
| SARIF | GitHub code scanning, so agent regressions sit next to dependency CVEs. |

Whatever you write around them, three things belong in the summary:

1. **What was tested and what was not.** Coverage, and the reason for every skip.
2. **The causes, not just the findings.** See above.
3. **What a pass does and does not mean.** Sinon puts this sentence in every
   report; do not delete it when you paste the findings into your own template.

Severity is about the outcome, not the elegance of the attack. A one-line
"ignore previous instructions" that moves money outranks a beautiful five-stage
chain that echoes a token.

---

## 7. Fixing, and re-testing

The remediation in each probe is specific, but the shape of the answer is almost
always the same: **the boundary has to be outside the model.**

- Retrieved content gets fenced structurally and normalised (strip zero-width
  characters, resolve visibility, apply NFKC and confusable folding) before it
  reaches the context.
- Tools are scoped by credential and by allowlist, not by a sentence in the
  system prompt. A read-only tool means a read-only database user.
- Irreversible actions are proposals the harness makes a human approve, and the
  approval names the exact target.
- Nothing sensitive lives in the system prompt, because it will leak eventually.
- Egress is allowlisted for every tool that takes a URL.
- Blast radius is capped in the tool: maximum recipients, maximum rows, maximum
  tool calls per turn.

Then re-run the same corpus and diff the JSON. Findings that moved from `fail` to
`pass` are fixed. Findings that moved to `skip` are not fixed — something changed
about what you can observe, and that needs explaining.

Wire the run into CI with `--fail-on high` so the fix stays fixed. Agent
behaviour regresses on a model upgrade, a prompt edit, or a new tool grant, and
none of those look like a security change in a diff.

---

## 8. What this methodology does not cover

Say so in the report rather than letting the reader assume.

- **The model itself.** Sinon tests an agent — a model plus its prompt, tools and
  harness. Swap the model and the results may change entirely.
- **Attacks nobody has written down.** The corpus is a floor, not a ceiling.
- **Multi-agent and agent-to-agent flows.** One agent under test at a time.
- **Training-time attacks.** Data poisoning, backdoors, model supply chain.
- **The classic surface underneath.** The web app, the API, the infrastructure
  the agent runs on all still need a normal pentest.
- **Rate of failure over time.** A run is a sample. `--repeat` helps; it does not
  make the result a probability.

---

## Checklist

```
[ ] Written authorization: client, authorizer, reference, window, hosts
[ ] engagement.yaml filled in from the signed RoE
[ ] Escalation contact confirmed reachable
[ ] Staging vs production decided; live tool blast radius understood
[ ] Trust boundary mapped; channels the corpus misses noted
[ ] Tool inventory, including what pairs compose into
[ ] Real system prompt obtained if possible
[ ] Baseline run (direct channel)
[ ] Full run, --repeat 3 if the target is a model, rate limited if production
[ ] Skips reviewed and explained
[ ] Heuristic findings confirmed by hand
[ ] Findings reduced to causes
[ ] Report states coverage, limits, and what a pass means
[ ] Re-test after fixes; CI gate added
```
