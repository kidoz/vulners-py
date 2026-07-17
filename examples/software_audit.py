"""Audit structured software metadata."""

from _env import load_dotenv

from vulners import Vulners
from vulners.types import AuditSoftware

load_dotenv()

with Vulners() as client:
    matches = client.audit.software((AuditSoftware(product="curl", vendor="haxx", version="8.0"),))

for match in matches:
    for vulnerability in match.vulnerabilities:
        print(vulnerability.id)
