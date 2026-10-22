"""A narrow publication gate: known assets, synthetic samples, secrets and runtime imports."""
import ast
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPORTS = {"docs/testing/2026-10-13-local.json", "docs/testing/2026-10-22-security-fixes.json",
                  "docs/testing/2026-10-22-security-fixes-final.json"}
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from endpoint_lab.scenarios import get_case, tuned_policy  # noqa: E402


def check_assets(root=ROOT):
    inventory = json.loads((root / "third-party-assets.json").read_text(encoding="utf-8"))
    for item in inventory["files"]:
        file = root / item["path"]
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Vendored asset/license differs from the reviewed inventory.")
    listed = {entry["path"] for entry in inventory["files"]}
    actual = {file.relative_to(root).as_posix() for file in (root / "src/endpoint_lab/web/assets").iterdir() if file.is_file()}
    if actual != listed:
        raise ValueError("Unreviewed asset in the web bundle.")


def check_samples(root=ROOT):
    expected = get_case("incident-chain")["events"]
    for directory in [root / "samples", root / "src/endpoint_lab/data"]:
        if json.loads((directory / "incident-chain.json").read_text(encoding="utf-8")) != expected:
            raise ValueError("Incident sample is not the original synthetic fixture.")
        if json.loads((directory / "tuned-policy.json").read_text(encoding="utf-8")) != tuned_policy():
            raise ValueError("Example policy differs from the synthetic preset.")
        from tools.generate_samples import make_xml
        if (directory / "incident-chain.xml").read_bytes() != make_xml(expected) + b"\n":
            raise ValueError("XML sample differs from the original generator output.")


def check_runtime(root=ROOT):
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if metadata["project"]["dependencies"]:
        raise ValueError("New runtime dependency needs a license review.")
    for file in (root / "src/endpoint_lab").rglob("*.py"):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            if any(name and name.split(".")[0] not in sys.stdlib_module_names | {"endpoint_lab"} for name in modules):
                raise ValueError("Unreviewed non-standard-library runtime import.")


def check_tracked_files(root=ROOT):
    result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                            cwd=root, capture_output=True, check=True)
    files = set(result.stdout.decode("utf-8").split("\0")) - {""}
    secret = re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
    approved_data = {"third-party-assets.json", "website/.openai/hosting.json"} | PUBLIC_REPORTS | {f"{base}/{name}" for base in ["samples", "src/endpoint_lab/data"] for name in ["incident-chain.json", "incident-chain.xml", "tuned-policy.json"]}
    for filename in files:
        file = root / filename
        if file.suffix.lower() in {".evtx", ".exe", ".dll", ".log", ".pcap", ".pem", ".key", ".pfx", ".p12"} or file.name.startswith(".env"):
            raise ValueError("Private telemetry, binaries or secrets must not be published.")
        if file.suffix in {".json", ".xml"} and filename not in approved_data:
            raise ValueError("Unreviewed JSON/XML data in the publication set.")
        if filename in PUBLIC_REPORTS:
            from tools.validation_support import validate_public_report
            validate_public_report(json.loads(file.read_text(encoding="utf-8")))
        if filename == "website/.openai/hosting.json":
            manifest = json.loads(file.read_text(encoding="utf-8"))
            if set(manifest) != {"project_id"} or not isinstance(manifest["project_id"], str) or not re.fullmatch(r"appgprj_[a-zA-Z0-9]+", manifest["project_id"]):
                raise ValueError("Unreviewed website hosting manifest.")
        if file.suffix in {".py", ".js", ".mjs", ".html", ".css", ".md", ".json", ".xml", ".yml", ".toml", ".cmd"}:
            if secret.search(file.read_text(encoding="utf-8")):
                raise ValueError("Potential secret in publication set; inspect locally.")


def main():
    check_assets()
    check_samples()
    check_runtime()
    check_tracked_files()
    print("Publication checks passed: asset hashes/notices, original synthetic samples, no extra runtime packages, selected secret/binary patterns.")
    print("This gate is not a legal audit or a complete secret scanner.")


if __name__ == "__main__":
    main()
