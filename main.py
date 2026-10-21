"""Run all Kavach agents in one process.  `python main.py` (Agentverse mailbox) or `python main.py --selftest`."""
import os
import sys
from pathlib import Path

# minimal .env loader (KEY=value lines); real env vars win
for line in (Path(__file__).parent / ".env").read_text().splitlines() if (Path(__file__).parent / ".env").exists() else []:
    k, _, v = line.partition("=")
    if v and not k.startswith("#"):
        os.environ.setdefault(k.strip(), v.strip())

if "--selftest" in sys.argv:
    os.environ["KAVACH_LOCAL"] = "1"

from uagents import Agent, Bureau, Context  # noqa: E402
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent  # noqa: E402

from kavach import link_agent, orchestrator, pattern_agent  # noqa: E402

bureau = Bureau(port=8000, endpoint="http://127.0.0.1:8000/submit")
for a in (orchestrator.agent, link_agent.agent, pattern_agent.agent):
    bureau.add(a)

if "--selftest" in sys.argv:
    SAMPLE = (
        "Congratulations! You are selected for Amazon Work From Home Internship without interview. Stipend Rs 25,000/month. "
        "Pay refundable security deposit of Rs 1,999 within 24 hours to confirm your seat to UPI hr.amazon@ybl. "
        "Fill details at https://amazon-careers-hiring.xyz/apply and contact HR on WhatsApp 9876543210. "
        "Mail: amazonhr.recruit@gmail.com"
    )
    tester = Agent(name="selftest", seed="kavach selftest seed")
    replies = []

    @tester.on_event("startup")
    async def go(ctx: Context):
        await ctx.send(orchestrator.agent.address, ChatMessage(content=[TextContent(type="text", text=SAMPLE)]))

    @tester.on_message(ChatMessage)
    async def got(ctx: Context, sender: str, msg: ChatMessage):
        print("\n=== KAVACH REPLY ===\n" + msg.text())
        assert any(c.type == "metadata" for c in msg.content), "verdict card missing"
        assert "HIGH RISK" in msg.text(), "sample scam not flagged"
        print("\nSELFTEST PASS", flush=True)
        os._exit(0)

    @tester.on_message(ChatAcknowledgement)
    async def ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
        pass

    bureau.add(tester)

if __name__ == "__main__":
    print(f"Kavach orchestrator address: {orchestrator.agent.address}")
    bureau.run()
