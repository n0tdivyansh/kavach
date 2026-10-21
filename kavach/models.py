from uagents import Model


class CheckRequest(Model):
    request_id: str
    text: str


class Finding(Model):
    weight: int  # risk points this finding adds
    tag: str  # scam category, e.g. "fee", "impersonation"
    detail: str


class Report(Model):
    request_id: str
    agent: str
    findings: list[Finding]
    summary: str = ""
