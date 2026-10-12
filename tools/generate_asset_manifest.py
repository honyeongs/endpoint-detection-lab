"""Record the exact vendored asset inventory, not a claim of legal certification."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src" / "endpoint_lab" / "web" / "assets"


def main():
    files = sorted([*ASSETS.glob("*.svg"), ASSETS / "LUCIDE-LICENSE.txt"])
    inventory = dict(schema_version=1, checked_on="2026-10-12", component="lucide-static", version="1.55.0",
        license="ISC", inherited_notice="Feather MIT notice preserved in upstream license file",
        source="https://www.npmjs.com/package/lucide-static/v/1.55.0", license_source="https://lucide.dev/license",
        files=[dict(path=file.relative_to(ROOT).as_posix(), sha256=hashlib.sha256(file.read_bytes()).hexdigest()) for file in files])
    (ROOT / "third-party-assets.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(files)} upstream asset/license files.")


if __name__ == "__main__":
    main()
