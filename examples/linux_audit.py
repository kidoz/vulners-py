"""Audit one installed Ubuntu package."""

from _env import load_dotenv

from vulners import Vulners

load_dotenv()

with Vulners() as client:
    result = client.audit.linux(
        "ubuntu",
        "22.04",
        ("curl 7.81.0-1ubuntu1.20 amd64",),
    )

for issue in result.issues:
    print(issue.package, issue.version, issue.fixed_version)
