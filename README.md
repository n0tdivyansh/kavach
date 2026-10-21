# Kavach 🛡️: a multi-agent scam shield for students

Fetch-A-Thon 3.0 (GCET Edition) submission. Built on Fetch.ai **uAgents**, registered on **Agentverse**, usable from **ASI:One** through the Agent Chat Protocol.

Students get fake internship offers ("pay a refundable deposit"), task scams ("earn ₹3,000/day liking videos") and "digital arrest" calls from fake CBI or customs officers. Kavach lets you paste the message into ASI:One and get back:

1. a **verdict** with a 0–100 risk score
2. the **evidence**: which links, domains, UPI IDs and phrases are suspicious, and why
3. **what to do now** (don't pay, hang up, call 1930, report on Sanchar Saathi)
4. a **pre-filled cybercrime.gov.in complaint**, plus an ASI:One interactive verdict card

## Agents

```
ASI:One user ──ChatMessage──▶ kavach (orchestrator, Chat Protocol, mailbox)
                                 │  CheckRequest (parallel)
                    ┌────────────┴─────────────┐
                    ▼                          ▼
          link-forensics               pattern-analyst
          RDAP domain age,             Indian scam-playbook rules
          brand lookalikes, TLDs,      + ASI:One LLM reasoning
          shorteners, UPI, free-mail
                    └──────── Report ──────────┘
                                 ▼
          verdict + evidence + actions + complaint + card ──▶ user
```

| Agent | File | Job |
|---|---|---|
| `kavach` | `kavach/orchestrator.py` | Chat Protocol entry point. Fans out, merges evidence, scores it, writes the reply and card. A 20 s timeout falls back to partial evidence. |
| `kavach-link-forensics` | `kavach/link_agent.py` | Extracts URLs, emails and UPI IDs. Checks domain age via public RDAP, lookalikes of 20 Indian brands, shorteners and cheap TLDs. |
| `kavach-pattern-analyst` | `kavach/pattern_agent.py` | 10 weighted rule families from real Indian scam playbooks, plus an ASI:One (`asi1-mini`) opinion when `ASI_ONE_API_KEY` is set. |

## Run

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: ASI_ONE_API_KEY, KAVACH_SEED
python main.py --selftest   # offline end-to-end test: fake Amazon internship → HIGH RISK
python main.py              # live: orchestrator connects to Agentverse via mailbox
```

To use it from ASI:One:
1. Run `python main.py`. Open the **Agent inspector** link it prints and click **Connect → Mailbox**.
2. On Agentverse, the agent `kavach` picks up `AGENTVERSE_README.md` as its profile. Make sure "Chat Protocol" shows under its protocols.
3. In ASI:One, ask *"Is this internship offer a scam? …"* or chat with the agent address directly.

## Data sources
- RDAP (rdap.org): public domain registration data
- India's official reporting channels: cybercrime.gov.in, the 1930 helpline and Sanchar Saathi (Chakshu)

## Roadmap
More specialists (screenshot OCR agent, phone-number reputation agent, a shared community scam-report registry agent), Hindi replies, and payment-protocol paid checks for colleges and placement cells.
