# The profile, version 0.1 (draft)

Generated from `patient_zero/data/controls.yaml` by `pz controls --markdown`. Do not edit by hand.

- **L0 Unprivileged:** No PHI. The product actively keeps PHI out. (5 controls)
- **L1 Helper:** Stores and processes PHI. AI features run only on BAA-covered models. No external assistants and no autonomous outbound actions on PHI. (35 controls)
- **L2 Agentic:** Agents act on PHI and external assistants may connect. (43 controls)

## GATE: Privilege gating

PHI is off by default; turning it on is an explicit, recorded act.

HIPAA 164.308(a)(4), 164.312(a)(1), 164.502(e), 164.504(e). SP 800-53 AC-3, AC-4, AC-6, CM-7, SC-7. CSF PR.AA, PR.DS.

- **GATE-1** (L0) PHI processing shall be disabled by default for every workspace.
- **GATE-2** (L0) Enabling PHI shall require an executed BAA on file, approval by a named owner, and an audit record.
- **GATE-3** (L0) PHI shall be stored and processed in a logically separate enclave with its own encryption keys, logs and access roles.
- **GATE-4** (L0) When a gate check cannot be completed, the system shall deny PHI access and continue in non-PHI mode.
- **GATE-5** (L0) Non-PHI workspaces shall tell users not to enter PHI and should detect and quarantine likely PHI on input.

## TRUST: Verified chain

No party touches PHI without a verified identity and a signed BAA.

HIPAA 164.308(b)(1), 164.314(a), 164.502(e). SP 800-53 SA-9, SR-3, IA-9, AC-20. CSF GV.SC.

- **TRUST-1** (L1) The operator shall keep a register of every subprocessor and model endpoint that can receive PHI, with BAA status, retention terms and training-use terms.
- **TRUST-2** (L1) The enclave shall send data only to endpoints on an allowlist drawn from that register, enforced at network egress.
- **TRUST-3** (L1) Model providers shall be contractually barred from training on PHI, and their retention period shall be documented.
- **TRUST-4** (L1) External assistant connections shall authenticate the client application, not only the user. Unverified clients shall be refused in PHI workspaces.
- **TRUST-5** (L1) Any change to the register shall trigger a risk review before deployment.

## AGENT: Agent identity and actions

Agents act with their own identity, narrower rights, and confirmation on disclosure.

HIPAA 164.312(a)(1), 164.312(c)(1), 164.312(d), 164.502(b). SP 800-53 AC-6, IA-9, AC-4, SI-10, SI-15. CSF PR.AA, PR.DS.

- **AGENT-1** (L2) Each agent and connected assistant shall have its own identity, distinct from the human user, in every log entry.
- **AGENT-2** (L2) Agent permissions shall never exceed the delegating user's and shall default to read-only in PHI workspaces.
- **AGENT-3** (L2) Actions that send PHI outside the workspace (email, SMS, export, webhook) or delete records shall require human confirmation that shows recipient and content.
- **AGENT-4** (L2) Content from records, documents, web pages and tool results shall be treated as untrusted data. It shall not be able to change an agent's permissions or destinations.
- **AGENT-5** (L2) When access is denied or data is missing, the agent shall say so. It shall not generate patient facts.
- **AGENT-6** (L2) Agent tokens shall be short-lived, scoped and revocable by the workspace owner, with revocation effective within 15 minutes.
- **AGENT-7** (L2) Output leaving the enclave shall pass a minimum-necessary filter.

## MEMORY: Learned context

Tenant and user scope is the default boundary for data and memory.

HIPAA 164.502(b), 164.312(c)(1), 164.310(d)(2)(i). SP 800-53 SC-4, SI-12, MP-6. CSF PR.DS.

- **MEM-1** (L1) Learned memory, embeddings and caches shall be scoped to one tenant, with no cross-tenant retrieval path.
- **MEM-2** (L1) PHI shall not be used to train or fine-tune shared models.
- **MEM-3** (L1) Every memory item derived from PHI shall be tagged with its source record.
- **MEM-4** (L1) Deleting a record shall remove derived memory, embeddings and cached prompts within the retention schedule.
- **MEM-5** (L1) Prompt and completion logs that contain PHI are PHI and shall receive the same protections.

## LOG: Audit

Every PHI event is recorded in a log that shows tampering.

HIPAA 164.312(b), 164.308(a)(1)(ii)(D). SP 800-53 AU-2, AU-3, AU-6, AU-9, AU-11, AU-12. CSF DE.CM, DE.AE.

- **LOG-1** (L1) The system shall record every PHI read, write, export, send, permission change and agent tool call, with user, agent, workspace, time and object.
- **LOG-2** (L1) The log shall be append-only and tamper-evident (hash chain or write-once storage) under a role separate from application admins.
- **LOG-3** (L1) Logs shall be retained per policy. Six years is recommended, to match HIPAA documentation retention.
- **LOG-4** (L1) Logs shall be reviewed on a schedule, with alerts on bulk reads, unusual exports and new connections.
- **LOG-5** (L1) Customers shall be able to export the log for their own workspace.

## MAP: Inventory and risk

The operator can enumerate every PHI store, flow and egress.

HIPAA 164.308(a)(1)(ii)(A), 164.308(a)(1)(ii)(B). SP 800-53 RA-3, CM-8, PM-5. CSF ID.AM, ID.RA, GV.RM.

- **MAP-1** (L1) The operator shall keep a current inventory of every system, store, queue, log and backup that holds PHI.
- **MAP-2** (L1) The operator shall keep a data flow map of every PHI path, including model calls and every egress.
- **MAP-3** (L1) A risk analysis shall be performed at least annually and before any new model, connector or subprocessor goes live.
- **MAP-4** (L1) Each identified risk shall have an owner, a treatment and a due date.

## BASE: Baseline safeguards

The ordinary Security Rule safeguards are in place before anything AI-specific.

HIPAA 164.312(a)(2), 164.312(d), 164.312(e)(1), 164.308(a)(5), 164.308(a)(6), 164.308(a)(7), 164.410, 164.504(e)(2). SP 800-53 IA-2, SC-8, SC-12, SC-28, CP-9, CP-10, IR-4, IR-6, AT-2. CSF PR.AA, PR.DS, PR.AT, RS.MA, RC.RP.

- **BASE-1** (L1) MFA shall be enforced for all users and administrators of PHI workspaces.
- **BASE-2** (L1) PHI shall be encrypted in transit (TLS 1.2 or later) and at rest, with keys held in a managed key service per enclave.
- **BASE-3** (L1) Every user shall have a unique ID. Shared accounts are prohibited and sessions shall time out.
- **BASE-4** (L1) Backups shall be encrypted and a restore shall be tested at least annually under a written contingency plan.
- **BASE-5** (L1) An incident response plan shall exist. Breach notice to the covered entity shall meet the BAA term and in no case exceed 60 days from discovery.
- **BASE-6** (L1) Workforce members shall be trained, provisioned by role and deprovisioned on exit.
- **BASE-7** (L1) PHI shall be returned or destroyed at contract end, with a destruction record.

## TEST: Verification

Controls are proven by repeatable tests, not by policy text.

HIPAA 164.308(a)(8). SP 800-53 CA-2, CA-8, RA-5, SA-11. CSF ID.RA, ID.IM.

- **TEST-1** (L1) Automated cross-tenant access tests shall run against every API route in CI.
- **TEST-2** (L1) An independent tester shall perform a penetration test at least annually, including AI abuse cases: prompt injection, permission escalation through agents, memory leakage and connector spoofing.
- **TEST-3** (L1) Vulnerability scans shall run at least every six months, with fix deadlines by severity.
- **TEST-4** (L1) Evidence for each control shall be collected automatically, dated and kept for the assessor.
- **TEST-5** (L2) An adversarial test suite shall run before each model, prompt or tool change ships.

HIPAA citations were checked to exist in eCFR on 2026-11-10. SP 800-53 and CSF identifiers are unchecked. The fit of every mapping is the author's judgment, not a legal opinion.
