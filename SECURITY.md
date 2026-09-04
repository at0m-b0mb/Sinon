# Security policy

## What Sinon is for

Testing AI agents **you own or have written authorization to test**. That is not
a disclaimer bolted onto an offensive tool — it is enforced. Any non-local target
requires an engagement file naming the client, the authorizing person, a
reference to that authorization and a date window that includes today, with the
target host in an explicit allowlist. The window is re-checked every run. There
is no `--force`.

Using this against a system you are not authorized to test is likely a crime in
your jurisdiction, and it is not what this project is for.

## Safety properties, and why they are there

**Requests are identifiable by default.** Every request carries `X-Sinon-Run`,
`X-Sinon-Probe` and `X-Sinon-Purpose: authorized-security-test`, and every canary
starts `SINON-` and encodes the run id. A defender who finds one in their logs at
3am can trace it to a specific authorized test instead of opening an incident.

Suppressing identification is possible — a detection-evasion exercise is a
legitimate engagement — but it requires a separate explicit flag in the
engagement file, it appears in the pre-flight banner, and it is stamped into the
report. It never happens quietly.

**The exfiltration sink is loopback-only.** The bind address is not
configurable. A sink reachable from the network is a data collector pointed at
someone else's traffic, and this project will not ship one. For targets a
loopback address cannot reach, supply your own collaborator URL with
`--sink-url`; Sinon then reports the probe as needing external correlation
rather than pretending it observed a result.

**The toolbelt touches nothing.** Every tool offered to a target is synthetic:
no socket is opened, no file is read, no mail is sent, no money moves. The tools
exist to be *observed*, not to act. The exception is the loopback sink, which the
operator starts themselves.

**Payloads are non-weaponised.** The corpus demonstrates publicly documented
technique classes using synthetic canaries, `evil-example.net` and a loopback
sink. No malware, no working exploit code, no real credentials, no impersonation
of a real company or person.

**The tool never claims safety.** The top grade is A, there is no A+, and every
report states that a pass is the absence of a finding rather than evidence of
safety.

## What this project will not build

Stated so that feature requests can be answered quickly and consistently:

- Covert operation as a default, or any feature whose purpose is to make an
  authorized test harder to attribute to the tester
- A network-reachable exfiltration sink
- Real, weaponised payloads: working exploit chains, malware, live collectors
- Impersonation of real organisations, brands or individuals in probe content
- Any bypass of the authorization gate
- Automated mass scanning of third-party agents

## Reporting a vulnerability in Sinon itself

Open a [private security advisory](https://github.com/at0m-b0mb/Sinon/security/advisories/new).
Please do not open a public issue first.

Things I consider vulnerabilities in this tool:

- Anything that lets a run proceed against an unauthorized target
- The sink binding anywhere other than loopback
- A toolbelt tool that performs a real-world side effect
- A path where a probe payload escapes the report as executable content (the
  HTML report escapes everything; a gap there is a bug)
- Credential or header leakage into reports or logs

## Handling Sinon's output

A Sinon report contains attacker-shaped text and, in the JSON, live canaries and
excerpts of whatever the target returned. Treat it as you would any pentest
artefact:

- The HTML report masks canaries for display; the JSON keeps them in full, on
  purpose, so a finding can be verified. Share the JSON accordingly.
- The target's responses may contain real customer data. Review before
  circulating.
- Do not paste report content into another agent without thinking about it. It
  is, by construction, full of prompt injections.
