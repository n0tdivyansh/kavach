"""Link forensics: URLs, domains, sender emails and UPI IDs found in the message."""
import re
from datetime import datetime, timezone

import requests
from uagents import Agent, Context

from .models import CheckRequest, Finding, Report

URL_RE = re.compile(r"(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(/\S*)?", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)
UPI_RE = re.compile(r"\b[\w.-]{2,}@(?:ok\w+|ybl|paytm|upi|apl|ibl|axl|ptyes|ptsbi|yapl|naviaxis)\b", re.I)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "t.co", "tiny.cc", "rebrand.ly"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me", "yahoo.in"}
RISKY_TLDS = {"xyz", "top", "click", "online", "site", "live", "buzz", "shop", "icu", "cfd", "sbs", "rest", "lol", "work"}
# brand -> its real domains; a brand name inside any other domain is a lookalike
BRANDS = {
    "google": {"google.com", "google.co.in"}, "amazon": {"amazon.in", "amazon.com", "amazon.jobs"},
    "tcs": {"tcs.com"}, "infosys": {"infosys.com"}, "wipro": {"wipro.com"}, "accenture": {"accenture.com"},
    "deloitte": {"deloitte.com"}, "flipkart": {"flipkart.com"}, "microsoft": {"microsoft.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "hdfc": {"hdfcbank.com"}, "icici": {"icicibank.com"},
    "paytm": {"paytm.com"}, "irctc": {"irctc.co.in"}, "unstop": {"unstop.com"},
    "internshala": {"internshala.com"}, "naukri": {"naukri.com"}, "linkedin": {"linkedin.com"},
    "fedex": {"fedex.com"}, "indiapost": {"indiapost.gov.in"},
}

agent = Agent(name="kavach-link-forensics", seed="kavach link forensics agent seed v1")


def domain_age_days(domain: str) -> int | None:
    """Registration age from public RDAP; None if unknown."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                born = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - born).days
    except Exception:
        pass
    return None


def registrable(domain: str) -> str:
    parts = domain.lower().split(".")
    # ponytail: naive eTLD+1 (handles co.in/gov.in style); use tldextract if this misfires
    return ".".join(parts[-3:]) if len(parts) > 2 and parts[-2] in {"co", "gov", "ac", "org", "net"} else ".".join(parts[-2:])


def domains_in(text: str) -> set[str]:
    """Web domains only: UPI IDs and email addresses are removed first so their halves aren't read as sites."""
    bare = EMAIL_RE.sub(" ", UPI_RE.sub(" ", text))
    return {registrable(m.group(1)) for m in URL_RE.finditer(bare) if not m.group(1)[-1].isdigit()}


def analyse(text: str) -> list[Finding]:
    out: list[Finding] = []
    emails = {m.group(0).lower() for m in EMAIL_RE.finditer(text)}
    upis = {m.group(0).lower() for m in UPI_RE.finditer(text)}
    domains = domains_in(text)

    for u in sorted(upis):
        out.append(Finding(weight=20, tag="payment", detail=f"Asks for payment to UPI ID `{u}`"))
    for e in sorted(emails - upis):
        d = e.split("@")[1]
        if d in FREE_MAIL:
            out.append(Finding(weight=12, tag="sender", detail=f"Recruiter/official uses free email `{e}` instead of a company domain"))
        else:
            domains.add(registrable(d))

    for d in sorted(domains):
        if d in SHORTENERS:
            out.append(Finding(weight=10, tag="link", detail=f"`{d}` is a URL shortener that hides the real destination"))
            continue
        if d.rsplit(".", 1)[-1] in RISKY_TLDS:
            out.append(Finding(weight=10, tag="link", detail=f"`{d}` uses a cheap TLD common in scam sites"))
        for brand, real in BRANDS.items():
            if brand in d.replace("-", "") and d not in real:
                out.append(Finding(weight=25, tag="lookalike", detail=f"`{d}` imitates {brand} (real: {', '.join(sorted(real))})"))
        age = domain_age_days(d)
        if age is not None and age < 180:
            out.append(Finding(weight=25, tag="link", detail=f"`{d}` was registered only {age} days ago"))
        elif age is not None:
            out.append(Finding(weight=0, tag="info", detail=f"`{d}` is {age // 365} yr old (age alone doesn't make it safe)"))
    return out


@agent.on_message(model=CheckRequest)
async def handle(ctx: Context, sender: str, msg: CheckRequest):
    findings = analyse(msg.text)
    ctx.logger.info(f"{msg.request_id}: {len(findings)} link findings")
    await ctx.send(sender, Report(request_id=msg.request_id, agent="link-forensics", findings=findings))
