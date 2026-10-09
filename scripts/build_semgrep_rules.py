"""Builds the offline Semgrep ruleset used by security_scan.
Run once during setup.sh, while there's still internet.

Semgrep parses every rule it's given on each run, and most of the registry
rulesets target languages we never scan. Keeping only the python/generic/regex
rules roughly halves the rule count, which is most of the hook's runtime.
"""

import ssl
import sys
from pathlib import Path
from urllib.request import urlopen

import certifi
import yaml

DATA_DIR = Path(__file__).parent.parent / "vericode" / "security_scan" / "data"
SOURCES = [
    "https://semgrep.dev/c/p/secrets",
    "https://semgrep.dev/c/p/security-audit",
    "https://semgrep.dev/c/r/python.lang.security.audit.dangerous-system-call",
]
KEEP = {"python", "generic", "regex"}


def fetch_rules(url: str) -> list[dict]:
    ctx = ssl.create_default_context(cafile=certifi.where())
    with urlopen(url, timeout=120, context=ctx) as resp:
        return yaml.safe_load(resp)["rules"]


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    rules, seen, total = [], set(), 0
    for url in SOURCES:
        print(f"Fetching {url}...")
        for rule in fetch_rules(url):
            total += 1
            # duplicate ids across rulesets make semgrep refuse to run
            if rule["id"] in seen or not KEEP & set(rule.get("languages", [])):
                continue
            seen.add(rule["id"])
            rules.append(rule)

    if not rules:
        sys.exit("No rules survived filtering - refusing to write an empty ruleset.")

    path = DATA_DIR / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False))
    print(f"Wrote {len(rules)} of {total} rules to {path}")


if __name__ == "__main__":
    main()
