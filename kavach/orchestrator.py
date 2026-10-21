"""Kavach: the ASI:One-facing agent. Fans a message out to specialist agents, merges their evidence
into one verdict, and hands back actions plus a ready-to-file cybercrime complaint."""
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    TextContent,
    chat_protocol_spec,
)
from uagents_core.contrib.protocols.chat.cards import CustomCardPayload, create_card_content

from . import link_agent, pattern_agent
from .models import CheckRequest, Report

SPECIALISTS = {"link-forensics": link_agent.agent.address, "pattern-analyst": pattern_agent.agent.address}
TIMEOUT_S = 20
# playbooks that are scams on their own, whatever else the message says
DECISIVE = {"fee", "upi-collect", "impersonation", "credentials", "too-good", "victim"}
PHONE_RE = re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b")

agent = Agent(
    name="kavach",
    port=8000,
    seed=os.getenv("KAVACH_SEED", "kavach dev seed"),
    mailbox=os.getenv("KAVACH_LOCAL") != "1",
    readme_path=str(Path(__file__).parent.parent / "AGENTVERSE_README.md"),
    description="Paste any suspicious job/internship offer, UPI request, SMS or 'digital arrest' call script. "
    "Kavach's agents check links, domains and scam patterns and tell you if it's a scam and what to do.",
)
chat = Protocol(spec=chat_protocol_spec)
pending: dict[str, dict] = {}  # request_id -> {sender, text, reports, t}

ACTIONS = {
    "victim": "Call **1930** NOW and file at https://cybercrime.gov.in: complaints in the first hour can get the money frozen in transit. "
              "Then call your bank to block the transaction and keep screenshots, UTR/transaction IDs and chat logs.",
    "upi-collect": "Decline the request. You never approve a payment or enter your UPI PIN to *receive* money.",
    "kyc": "Banks never ask you to update KYC via an SMS link. Use only the bank's official app or visit a branch.",
    "fee": "Don't pay any 'registration / security / training' fee. Real employers never charge you to join.",
    "impersonation": "No police, CBI, ED or customs officer can 'digitally arrest' you or ask for money on a video call. Hang up.",
    "credentials": "Never share OTP, Aadhaar, PAN or bank details. If you installed AnyDesk/TeamViewer, uninstall it and call your bank.",
    "too-good": "'Earn daily by liking videos / rating hotels' is the task scam: the first payouts are bait for bigger deposits.",
    "sender": "Verify the offer on the company's official careers page or LinkedIn, not via the sender's contact details.",
    "lookalike": "The link imitates a real brand. Check the spelling of the domain against the official site.",
    "link": "Don't open the link or log in there. Type the official website address yourself.",
}


def verdict(score: int) -> tuple[str, str]:
    if score >= 60:
        return "HIGH RISK: almost certainly a scam", "warning"
    if score >= 30:
        return "SUSPICIOUS: verify before you act", "warning"
    return "LOW RISK: no strong scam signals found", "success"


def build_reply(text: str, reports: list[Report]) -> tuple[str, CustomCardPayload]:
    findings = sorted((f for r in reports for f in r.findings), key=lambda f: -f.weight)
    tags = {f.tag for f in findings}
    score = min(100, sum(f.weight for f in findings))
    if tags & DECISIVE:
        score = max(score, 70)
    label, variant = verdict(score)
    if "victim" in tags:
        label = "ACT NOW: you may already have been scammed"
    actions = [a for t, a in ACTIONS.items() if t in tags]
    if score >= 30 and "victim" not in tags:
        actions.append("Report it at https://cybercrime.gov.in or call **1930** (if money was lost, call within the first hour). "
                       "Report the number/SMS on Sanchar Saathi → Chakshu (https://sancharsaathi.gov.in).")
    elif score < 30:
        actions.append("Still verify independently before sharing documents or paying anything.")
    evidence = [f.detail for f in findings if f.weight > 0] or ["No red flags matched."]
    notes = [r.summary for r in reports if r.summary]
    missing = set(SPECIALISTS) - {r.agent for r in reports}

    ids = sorted({*PHONE_RE.findall(text), *link_agent.UPI_RE.findall(text), *link_agent.domains_in(text)})
    complaint = (
        f"Category: Online financial fraud / {', '.join(sorted(tags - {'info'})) or 'suspicious communication'}\n"
        f"Date received: {datetime.now(timezone.utc):%d %b %Y}\n"
        f"Suspect identifiers: {', '.join(ids) or 'TODO: add sender number / UPI / link'}\n"
        f"Description: I received the following message which shows signs of fraud ({'; '.join(evidence[:3])}).\n"
        f"Message: \"{text[:600]}\""
    )

    md = [f"## {label}  ({score}/100)", "", "**Why**", *[f"- {e}" for e in evidence]]
    if notes:
        md += ["", *notes]
    md += ["", "**What to do now**", *[f"{i}. {a}" for i, a in enumerate(actions, 1)]]
    if score >= 30:
        md += ["", "**Ready-to-file complaint** (paste into cybercrime.gov.in → Report other cybercrime)", "```", complaint, "```"]
    if missing:
        md += ["", f"_Note: {', '.join(missing)} didn't answer in time; verdict uses partial evidence._"]
    md += ["", "_Checked by Kavach agents: link-forensics (RDAP domain age, lookalikes, UPI/email) + pattern-analyst (Indian scam playbooks + ASI:One)._"]

    card = CustomCardPayload.model_validate({"root": {"type": "section", "title": "Kavach verdict", "children": [
        {"type": "group", "direction": "row", "gap": 8, "children": [
            {"type": "badge", "label": f"{score}/100", "variant": variant},
            {"type": "heading", "value": label, "level": 2}]},
        {"type": "section", "title": "Evidence", "children": [{"type": "list", "items": [
            {"children": [{"type": "text", "value": e}]} for e in evidence[:6]]}]},
        {"type": "section", "title": "Do this now", "children": [{"type": "list", "items": [
            {"children": [{"type": "text", "value": a.replace("**", "")}]} for a in actions]}]},
    ]}})
    return "\n".join(md), card


async def finish(ctx: Context, rid: str):
    job = pending.pop(rid, None)
    if not job:
        return
    text, card = build_reply(job["text"], list(job["reports"].values()))
    st = await ctx.send(job["sender"], ChatMessage(content=[
        TextContent(type="text", text=text),
        create_card_content(card, is_terminal=True),
        EndSessionContent(type="end-session"),
    ]))
    ctx.logger.info(f"{rid}: verdict sent ({len(job['reports'])}/{len(SPECIALISTS)} reports): {st.status} {st.detail}")


@chat.on_message(ChatMessage)
async def on_chat(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))
    text = msg.text().strip()
    if not text:
        return
    if len(text) < 25:
        await ctx.send(sender, ChatMessage(content=[TextContent(type="text", text=(
            "Hi, I'm **Kavach** 🛡️. Paste the full suspicious message: internship/job offer, UPI payment request, "
            "SMS, email or what a 'police officer' said on the call. Include any links, numbers or UPI IDs. "
            "I'll tell you if it's a scam and what to do next."))]))
        return
    rid = str(uuid4())
    pending[rid] = {"sender": sender, "text": text, "reports": {}, "t": time.time()}
    for addr in SPECIALISTS.values():
        st = await ctx.send(addr, CheckRequest(request_id=rid, text=text))
        ctx.logger.info(f"send {addr[:14]}: {st.status} {st.detail} {st.endpoint}")
    ctx.logger.info(f"{rid}: dispatched to {len(SPECIALISTS)} specialists")


@chat.on_message(ChatAcknowledgement)
async def on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    pass


@agent.on_message(model=Report)
async def on_report(ctx: Context, sender: str, rep: Report):
    job = pending.get(rep.request_id)
    if not job:
        return
    job["reports"][rep.agent] = rep
    if len(job["reports"]) == len(SPECIALISTS):
        await finish(ctx, rep.request_id)


@agent.on_interval(period=5.0)
async def sweep(ctx: Context):
    for rid in [r for r, j in pending.items() if time.time() - j["t"] > TIMEOUT_S]:
        await finish(ctx, rid)


agent.include(chat, publish_manifest=True)
