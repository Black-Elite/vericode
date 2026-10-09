"""Builds the offline package-name snapshots used by import_check.
Run once during setup.sh, while there's still internet.

Writes two newline-separated files of PEP 503-normalized names:
  pypi_all.txt  - every project on PyPI (does this name exist at all?)
  pypi_top.txt  - top ~15k by downloads (is it well known?)
"""

import json
import re
import ssl
from pathlib import Path
from urllib.request import Request, urlopen

import certifi

DATA_DIR = Path(__file__).parent.parent / "vericode" / "import_check" / "data"
SIMPLE_INDEX_URL = "https://pypi.org/simple/"
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_json(url: str, accept: str = "application/json") -> dict:
    req = Request(url, headers={"Accept": accept, "User-Agent": "vericode-setup"})
    ctx = ssl.create_default_context(cafile=certifi.where())
    with urlopen(req, timeout=120, context=ctx) as resp:
        return json.load(resp)


def write_names(path: Path, names: set[str]) -> None:
    path.write_text("\n".join(sorted(names)) + "\n")
    print(f"Wrote {len(names):,} names to {path}")


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("Fetching full PyPI index (~45MB)...")
    index = fetch_json(SIMPLE_INDEX_URL, accept="application/vnd.pypi.simple.v1+json")
    write_names(DATA_DIR / "pypi_all.txt", {normalize(p["name"]) for p in index["projects"]})

    print("Fetching top PyPI packages...")
    top = fetch_json(TOP_PACKAGES_URL)
    write_names(DATA_DIR / "pypi_top.txt", {normalize(r["project"]) for r in top["rows"]})


if __name__ == "__main__":
    main()
