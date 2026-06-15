# AgentGate

**Your agent just read 847 files in 4 minutes. Your logs show 847 authorized requests. AgentGate saw a kill chain.**

[![PyPI version](https://img.shields.io/pypi/v/agentgate-pdp.svg)](https://pypi.org/project/agentgate-pdp/)
[![npm version](https://img.shields.io/npm/v/agentgate-pdp.svg)](https://www.npmjs.com/package/agentgate-pdp)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

```bash
pip install agentgate-pdp      # Python
npm install agentgate-pdp      # TypeScript / Node.js
```

**Website:** [tryagentgate.com](https://tryagentgate.com) · **Full demo:** [youtube.com/watch?v=SJQMBv1YTwE](https://youtu.be/SJQMBv1YTwE)

> ⭐ If AgentGate saves you from a rogue agent, star the repo — it helps others find it.

---

## What builders are saying

> *"We are studying AgentGate closely — the Merkle-chained artifact approach is a compelling pattern for high-stakes agent actions."*
> — Kirill (Fenix), [ATAP](https://github.com/gugli4ifenix-design/atap) author

> *"The pre-execution evidence framing is interesting — especially the distinction between authorization evidence that exists before consequence versus audit logs assembled afterward."*
> — Dale Chou, agent governance researcher

---

## The attack OAuth can't see

Your LangGraph agent has a valid token. It reads 10 reports — each request is authorized. Then it tries to export everything. Each individual request looked clean. The kill chain only becomes visible across the sequence.

```
[REQUEST]  action=read  resource=/reports/q1.pdf       → PERMIT  (trust=0.91)
[REQUEST]  action=read  resource=/reports/q2.pdf       → PERMIT  (trust=0.89)
[REQUEST]  action=read  resource=/reports/q3.pdf       → PERMIT  (trust=0.87)
...7 more reads in under 5 minutes...

[REQUEST]  action=export  resource=/reports/*
[KILL CHAIN] *** BULK_READ_THEN_EXFIL detected ***
             10 reads in 4m32s followed by export attempt
             Pattern: data enumeration → exfiltration

[DECISION] *** DENY ***
[REASON]   Kill chain: bulk read then exfiltration sequence.
           No single request triggered this. The sequence did.

[AUDIT]    entry #4821 — HMAC-chained, tamper-evident
[ALERT]    security team notified instantly
```

OAuth checked *who the agent was*. AgentGate checks *what the sequence means*.

![AgentGate dashboard — kill chain detection in real time](demo_agentgate.gif)

> **Stateful vs stateless:** Most governance tools — including Microsoft's Agent Governance Toolkit — evaluate each request independently. They cannot detect BULK_READ_THEN_EXFIL because no single request is suspicious. AgentGate tracks behavioral patterns across 24-hour sessions. The sequence is the attack. Only a stateful system can see it.

---

## Quick start

**One-command attack demo** — no `.env`, no config. Spins up AgentGate, runs 5 live attack phases, and shows each decision in the dashboard:

```bash
git clone https://github.com/ElamOlame31/agentgate
cd agentgate
docker compose -f docker-compose.demo.yml up
# Dashboard → http://localhost:8000
```

AgentGate starts, loads the trust-scoring models, then the demo container runs automatically. Every attack is blocked and logged to the dashboard in real time.

**Production setup:**

```bash
cp .env.example .env   # set AGENTGATE_API_KEY
pip install -r requirements.txt
python run.py
# Dashboard → http://localhost:8000
```

Or with Docker:

```bash
docker compose up
```

Install the SDK:

```bash
pip install agentgate-pdp           # Python
npm install agentgate-pdp           # TypeScript / Node.js
```

---

## How it works

Every agent declares its identity and purpose at registration time. Every action gets evaluated against that contract — plus real-time behavioral patterns — before it runs.

```python
from agentgate import AgentGate

gate = AgentGate("http://localhost:8000", api_key="your-key")

gate.register(
    agent_id="report_bot",
    name="ReportBot",
    declared_purpose="Summarize quarterly business reports for the executive team",
    authorized_resources=["/reports/*", "/documents/public/*"],
    authorized_actions=["read", "search"],
)

# Permitted — within scope and purpose
result = gate.authorize("read", "/reports/q3.pdf")
# {"decision": "PERMIT", "trust_score": 91, "explanation": "..."}

# Blocked — out of scope, purpose mismatch, velocity anomaly
result = gate.authorize("delete", "/hr/salary.xlsx")
# raises AgentGateDenied: DENY — RESOURCE_OUT_OF_SCOPE, PURPOSE_MISMATCH
```

Trust is scored across 4 dimensions:

| Dimension | Weight | What it checks |
|-----------|--------|----------------|
| Identity | 25% | Token validity, action/resource match against declared scope |
| Delegation | 25% | Full chain walk — child agents can never exceed parent scope |
| Purpose Alignment | 30% | Semantic embedding similarity: does this action match what the agent said it would do? |
| Behavioral | 20% | Real-time velocity vs. per-agent baseline — detects exfiltration patterns |

---

## What gets blocked

| Attack | Response |
|--------|----------|
| Agent reads `/confidential/salary.xlsx` (out of scope) | `DENY — RESOURCE_OUT_OF_SCOPE` |
| Agent calls `delete` (not in authorized actions) | `DENY — UNAUTHORIZED_ACTION` |
| Child agent claims more scope than parent granted | `DENY — CHAIN_SCOPE_VIOLATION` |
| Agent fires 80 requests/min (data exfiltration pattern) | `DENY — CRITICAL_VELOCITY` |
| Agent that has only read/searched for hours suddenly attempts `delete` | `ESCALATE — ACTION_TYPE_ESCALATION` |
| Document says "ignore your previous instructions" | Blocked before agent reads it |
| Prompt injection in tool output or external content | Hybrid keyword + semantic scan |
| Unknown agent attempts access | `DENY — UNREGISTERED_AGENT` |
| Secret or API key in resource path | `DENY — SECRET_IN_ARGS` |

---

## Integrations

### Python (sync + async)

```python
from agentgate import AgentGate, AsyncAgentGate

# Sync
gate = AgentGate("http://localhost:8000", api_key="your-key")
gate.register("bot", "Bot", "Read reports", ["/reports/*"], ["read"])
gate.authorize("read", "/reports/q3.pdf")

# Async — LangGraph, CrewAI, AutoGen
gate = AsyncAgentGate("http://localhost:8000", api_key="your-key")
await gate.register("bot", "Bot", "Read reports", ["/reports/*"], ["read"])
await gate.authorize("read", "/reports/q3.pdf")

# Decorator
@gate.guard("read", resource_arg="path")
async def read_document(path: str) -> str:
    return open(path).read()

# Context manager
async with gate.operation("write", "/reports/output.pdf"):
    await write_report(data)
```

### TypeScript / Node.js

```typescript
import AgentGate, { AgentGateDeniedError } from "agentgate-pdp";

const gate = new AgentGate({ url: "http://localhost:8000", apiKey: "your-key" });

await gate.register({
  agent_id:             "report_bot",
  name:                 "ReportBot",
  declared_purpose:     "Summarize quarterly business reports",
  authorized_resources: ["/reports/*"],
  authorized_actions:   ["read"],
});

try {
  const result = await gate.authorize("read", "/reports/q3.pdf");
  console.log(result.decision);        // "PERMIT"
  console.log(result.trust_breakdown); // { identity: 92, delegation: 100, ... }
} catch (err) {
  if (err instanceof AgentGateDeniedError) {
    console.log("Blocked:", err.message);
  }
}
```

### LangChain

```python
from agentgate.langchain import AgentGateToolkit
from langchain.agents import create_react_agent

toolkit = AgentGateToolkit(
    agentgate_url="http://localhost:8000",
    api_key="your-key",
    agent_id="report_agent",
    name="ReportBot",
    declared_purpose="Summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
    processes_external_content=True,   # enables prompt injection scanning on tool output
)

safe_tools = toolkit.wrap([read_document, list_documents, send_summary])
agent = create_react_agent(llm, safe_tools)
# Every tool call is intercepted and authorized before executing
```

### AutoGen

```python
from agentgate.autogen import AgentGateToolkit

toolkit = AgentGateToolkit(
    agentgate_url="http://localhost:8000",
    api_key="your-key",
    agent_id="autogen_agent",
    name="AutoGenBot",
    declared_purpose="Analyze and summarize business documents",
    authorized_resources=["/documents/*"],
    authorized_actions=["read", "search"],
)

safe_functions = toolkit.wrap([read_file, search_db, write_summary])
# Use safe_functions as AutoGen FunctionTool list
```

### OpenAI Agents SDK

```python
from agentgate.openai_agents import AgentGateToolkit

toolkit = AgentGateToolkit(
    agentgate_url="http://localhost:8000",
    api_key="your-key",
    agent_id="openai_agent",
    name="OpenAIBot",
    declared_purpose="Retrieve and summarize customer data for support team",
    authorized_resources=["/customers/*"],
    authorized_actions=["read"],
)

tools = toolkit.wrap([get_customer, search_tickets])
# Raises PermissionError on DENY — agent handles it as a tool error
```

### Vercel AI SDK

```typescript
import { tool } from "ai";
import { z } from "zod";

const readReport = tool({
  description: "Read a quarterly report",
  parameters: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    await gate.authorize("read", path, "AI assistant reading report");
    return fs.readFile(path, "utf-8");
  },
});
```

---

## Natural language policies

Type a rule in plain English from the dashboard, or via API:

```python
import httpx

httpx.post(f"{url}/policies", json={"rule": "Agents must never delete files"})
httpx.post(f"{url}/policies", json={"rule": "No access to /hr data outside business hours"})
httpx.post(f"{url}/policies", json={"rule": "Escalate any write operation to /finance"})
```

Rules are parsed by Claude and run as hard blocks **before** trust scoring — a policy DENY is always final.

---

## Compliance templates

Apply a full compliance policy set with one API call:

```bash
# SOC 2 Type II — 7 policies covering CC6/CC7/CC9 controls
curl -X POST http://localhost:8000/templates/soc2/apply -H "X-API-Key: your-key"

# HIPAA — PHI access control, minimum necessary, bulk operation restrictions
curl -X POST http://localhost:8000/templates/hipaa/apply -H "X-API-Key: your-key"

# GDPR — purpose limitation, special categories, right to erasure
curl -X POST http://localhost:8000/templates/gdpr/apply -H "X-API-Key: your-key"

# Financial Services — PCI-DSS, SOX, insider trading controls
curl -X POST http://localhost:8000/templates/financial_services/apply -H "X-API-Key: your-key"
```

Templates are also accessible as one-click buttons in the dashboard.

---

## Tamper-proof audit trail

Every authorization decision is sealed before the action executes — not logged afterward. The record precedes what it authorizes.

Every decision is cryptographically chained with HMAC-SHA256. The audit trail can be exported as PDF or CSV for compliance review, and verified for integrity:

```bash
# Verify the audit log has not been tampered with
curl http://localhost:8000/audit/verify -H "X-API-Key: your-key"
# {"valid": true, "entries_verified": 1482, "broken_at": null}

# Export a compliance report (30-day window)
curl "http://localhost:8000/audit/export?format=pdf&from_ts=1700000000&to_ts=1702678400" \
     -H "X-API-Key: your-key" -o report.pdf
```

The dashboard also includes a date-range export modal — click **Export Report** to download.

---

## SIEM integration

AgentGate forwards every decision to your existing SIEM. Two env vars — no new tooling.

### Splunk (HTTP Event Collector)

```env
AGENTGATE_SPLUNK_HEC_URL=https://splunk.yourcompany.com:8088
AGENTGATE_SPLUNK_TOKEN=your-hec-token
AGENTGATE_SPLUNK_INDEX=main    # optional
```

Events land as `sourcetype=agentgate:decision` with all trust score dimensions as structured fields. Query immediately in Splunk Search.

### Microsoft Sentinel

```env
AGENTGATE_SENTINEL_WORKSPACE_ID=your-workspace-id
AGENTGATE_SENTINEL_KEY=your-primary-key
AGENTGATE_SENTINEL_LOG_TYPE=AgentGateDecision    # optional
```

Creates an `AgentGateDecision` table in your Log Analytics workspace. Query with KQL.

Unlike incident alerts (DENY/ESCALATE only), SIEM connectors forward **every** decision — PERMIT included — so your analysts see the full picture.

---

## Human-in-the-loop approvals

```python
gate.register(..., requires_human_approval=True)

# On ESCALATE, the agent pauses here.
# Human sees the request in the dashboard and approves or denies.
# The SDK polls automatically and unblocks when a decision is made.
result = gate.authorize("read", "/confidential/merger_details.pdf")
# Auto-denies after 90 seconds if no response.
```

Push notifications via ntfy.sh include one-tap Approve/Deny action buttons.

---

## Multi-agent delegation

AgentGate enforces scope attenuation across the full delegation chain. A child agent can never exceed what its parent was authorized to do — enforced at both registration and authorization time.

```python
# Root orchestrator has broad scope
gate.register("orchestrator", "Orchestrator", "Manage document workflow",
              authorized_resources=["/documents/*"], authorized_actions=["read", "write"])

# Analyst is delegated a strict subset
httpx.post(f"{url}/agents/delegate", json={
    "parent_agent_id":  "orchestrator",
    "parent_token":     orchestrator_token,
    "child_agent_id":   "analyst",
    "child_resources":  ["/documents/public/*"],  # subset of parent
    "child_actions":    ["read"],                  # subset of parent
})

# Analyst tries /confidential/ — chain walk detects it
# {"decision": "DENY", "attack_flags": ["CHAIN_SCOPE_VIOLATION"]}
```

---

## Architecture

```
Your Agent (LangChain / AutoGen / OpenAI Agents / custom)
    │
    │   pip install agentgate-pdp   |   npm install agentgate-pdp
    ▼
AgentGate SDK ──── POST /authorize ────► AgentGate PDP Server
                                              │
                                    ┌─────────┴──────────────┐
                                    │ Policy Engine           │
                                    │ (NL rules, hard block)  │
                                    ├────────────────────────┤
                                    │ Injection Detector      │
                                    │ (keyword + semantic)    │
                                    ├────────────────────────┤
                                    │ 4D Trust Scoring        │
                                    │  Identity      (25%)    │
                                    │  Delegation    (25%)    │
                                    │  Purpose       (30%)    │
                                    │  Behavioral    (20%)    │
                                    ├────────────────────────┤
                                    │ HITL Approval queue     │
                                    ├────────────────────────┤
                                    │ HMAC-signed Audit Log   │
                                    │ (PDF / CSV export)      │
                                    └────────────┬───────────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              ▼                  ▼                  ▼
                         Dashboard          Splunk HEC       MS Sentinel
                         (real-time)        (SIEM)           (SIEM)
                              │
                    PERMIT / ESCALATE / DENY
                              │
                    Tool executes (or doesn't)
```

---

## Configuration

```env
# Required
AGENTGATE_API_KEY=your-secret-key-min-24-chars

# Optional — enables NL policy parsing and purpose scoring
ANTHROPIC_API_KEY=sk-ant-...

# Alerts (DENY / ESCALATE)
AGENTGATE_ALERT_TOPIC=agentgate-yourname     # ntfy.sh push notifications
AGENTGATE_WEBHOOK_URL=https://hooks.slack.com/... # or Teams webhook

# SIEM (every decision)
AGENTGATE_SPLUNK_HEC_URL=https://splunk.yourcompany.com:8088
AGENTGATE_SPLUNK_TOKEN=your-hec-token
AGENTGATE_SENTINEL_WORKSPACE_ID=your-workspace-id
AGENTGATE_SENTINEL_KEY=your-primary-key

# Audit log integrity
AGENTGATE_LOG_KEY=your-hmac-signing-key

# Server
AGENTGATE_PORT=8000
AGENTGATE_AUDIT_RETENTION_DAYS=90
```

---

## Why not OPA / OpenFGA / Microsoft AGT?

OPA and OpenFGA answer: *"Can user X access resource Y?"* — static rules evaluated against static state. Microsoft's Agent Governance Toolkit added agent-aware policies, but evaluates each request independently — it has no memory of what the agent did 4 minutes ago.

AgentGate answers: *"Should this specific agent action be allowed right now, given what this agent has been doing and what it said its purpose is?"*

The record precedes what it authorizes.

| Capability | OPA / OpenFGA | Microsoft AGT | AgentGate |
|------------|---------------|---------------|-----------|
| Static resource access control | ✓ | ✓ | ✓ |
| Agent-aware policy evaluation | ✗ | ✓ | ✓ |
| Stateful behavioral analysis (24h) | ✗ | ✗ | ✓ |
| Kill chain detection across sessions | ✗ | ✗ | ✓ |
| Purpose alignment (did the agent drift?) | ✗ | ✗ | ✓ |
| Delegation chain integrity | ✗ | Partial | ✓ |
| Prompt injection detection | ✗ | ✗ | ✓ |
| Human-in-the-loop approval | ✗ | ✗ | ✓ |
| Pre-execution Merkle audit seal | ✗ | ✗ | ✓ |
| Compliance audit trail (PDF/CSV) | ✗ | Limited | ✓ |
| SIEM integration | via plugin | ✗ | native |
| Open source | ✓ | ✓ | ✓ |
| Self-hosted | ✓ | ✓ | ✓ |

Use OPA for your human users. Use AgentGate for your agents.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Elam Olame Mugabo](https://elamolamemugabo.com) · [tryagentgate.com](https://tryagentgate.com)
