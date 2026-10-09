"""Builds the offline PyPI package name snapshot used by import_check.
Run once during setup.sh, while there's still internet. Owner: Person B.
"""

import json
from pathlib import Path
from urllib.request import urlopen

OUTPUT = Path(__file__).parent.parent / "vericode" / "import_check" / "pypi_snapshot.json"
SIMPLE_INDEX_URL = "https://pypi.org/simple/"


def main() -> None:
    # TODO: fetch https://pypi.org/simple/ (plain HTML list of all package
    # names), or use a trimmed "top N packages" list instead of the full
    # index if that's faster to generate and sufficient for the demo.
    names: list[str] = []
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(sorted(set(names))))
    print(f"Wrote {len(names)} package names to {OUTPUT}")


if __name__ == "__main__":
    main()
