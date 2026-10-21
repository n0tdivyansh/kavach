"""Scam-pattern analyst: known Indian fraud playbooks (rules) + ASI:One reasoning when a key is set."""
import json
import os
import re

from openai import AsyncOpenAI
from uagents import Agent, Context

from .models import CheckRequest, Finding, Report

# (weight, tag, regex, what it means)
RULES = [
    (30, "fee", r"registration fee|security deposit|refundable (?:amount|deposit|fee)|deposit (?:of|to unlock|to withdraw)|training fee|kit (?:fee|charge)|processing fee|joining fee|pay .{0,20}(?:to confirm|to proceed|to activate)", "Demands money before you start work — real employers never charge you"),
    (15, "payment", r"\bupi\b|google ?pay|phone ?pe|gpay|paytm|scan (?:the )?qr|₹ ?\d|rs\.? ?\d|inr ?\d", "Payment instructions inside the offer"),
    (12, "urgency", r"within \d+ ?(?:hours|hrs|minutes|mins)|immediately|urgent|last (?:date|chance)|today only|limited seats|expires? (?:today|soon)", "Artificial urgency to stop you from verifying"),
    (12, "off-platform", r"whats ?app|telegram|signal app", "Moves the conversation to WhatsApp/Telegram"),
    (20, "too-good", r"(?:earn|income|salary|stipend).{0,30}(?:per day|daily|/day)|like (?:videos|posts)|rate (?:hotels|products)|task[- ]based|part[- ]time.{0,20}(?:earn|income)|work from home.{0,30}earn", "Unrealistic pay for trivial tasks (task/like scam)"),
    (35, "impersonation", r"\bcbi\b|enforcement directorate|\bed officer|narcotics|customs|\btrai\b|cyber ?cell|police (?:officer|station)|digital arrest|money laundering|drugs? (?:found|parcel)|fedex|parcel (?:seized|held)", "Claims to be police/CBI/customs — the 'digital arrest' playbook"),
    (25, "secrecy", r"don'?t tell|do not (?:tell|inform|share with)|keep (?:this )?(?:confidential|secret)|stay on (?:the )?(?:video )?call|do not disconnect", "Isolates you from family and friends"),
    (30, "credentials", r"\botp\b|aadhaar|\bpan\b|cvv|net ?banking|bank (?:details|password)|anydesk|teamviewer|screen ?share|quick ?support", "Asks for OTP / ID / bank access or a remote-access app"),
    (15, "no-interview", r"selected without (?:an )?interview|no interview|direct (?:selection|joining)|you (?:have been|are) (?:shortlisted|selected)", "Selected without any interview"),
    (40, "victim", r"already (?:paid|transferred|sent|lost)|i (?:have )?(?:paid|transferred|lost)|money (?:is )?gone|(?:got|been|was) scammed|fake (?:job )?consultancy", "You may already have lost money: act within the golden hour"),
    (30, "upi-collect", r"collect request|approve .{0,40}(?:to (?:claim|receive|get))|enter (?:your )?(?:upi )?pin to (?:receive|claim)|cashback|refund", "UPI collect/'refund' trick: approving a request or entering your PIN sends money, never receives it"),
    (30, "kyc", r"\bkyc\b|account (?:will be |has been )?(?:blocked|suspended|frozen)|update (?:your )?(?:bank|pan|kyc)", "Fake KYC-expiry / account-block alert"),
    (10, "lottery", r"lottery|lucky draw|you (?:have )?won|prize money|kbc", "Prize/lottery bait"),
]

agent = Agent(name="kavach-pattern-analyst", seed=os.getenv("KAVACH_SEED", "kavach dev seed") + " pattern-analyst")
llm = AsyncOpenAI(api_key=os.environ["ASI_ONE_API_KEY"], base_url="https://api.asi1.ai/v1") if os.getenv("ASI_ONE_API_KEY") else None

PROMPT = """You are a fraud analyst for Indian students. Read the message and reply with JSON only:
{"scam_type": "<short name or 'none'>", "risk": <0-100>, "reasoning": "<2 sentences, plain English>"}
Message:
"""


def rule_findings(text: str) -> list[Finding]:
    low = text.lower()
    return [Finding(weight=w, tag=tag, detail=why) for w, tag, rx, why in RULES if re.search(rx, low)]


async def llm_opinion(text: str) -> str:
    if not llm:
        return ""
    try:
        r = await llm.chat.completions.create(
            model=os.getenv("ASI_ONE_MODEL", "asi1-mini"),
            messages=[{"role": "user", "content": PROMPT + text[:4000]}],
            temperature=0,
        )
        raw = r.choices[0].message.content
        j = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])
        return f"ASI:One read: **{j['scam_type']}** ({j['risk']}/100). {j['reasoning']}"
    except Exception:
        return ""


@agent.on_message(model=CheckRequest)
async def handle(ctx: Context, sender: str, msg: CheckRequest):
    findings = rule_findings(msg.text)
    summary = await llm_opinion(msg.text)
    ctx.logger.info(f"{msg.request_id}: {len(findings)} pattern findings, llm={'yes' if summary else 'no'}")
    await ctx.send(sender, Report(request_id=msg.request_id, agent="pattern-analyst", findings=findings, summary=summary))
