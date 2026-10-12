import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze_bytes
from .io import read_local, write_new
from .limits import InputError
from .parsing import strict_json
from .scenarios import tuned_policy
from .validation import compare_policies


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local endpoint log lab; not an EDR or a malware verdict.")
    commands = parser.add_subparsers(dest="command", required=True)
    analysis = commands.add_parser("analyze")
    analysis.add_argument("file", type=Path)
    analysis.add_argument("--format", choices=["auto", "json", "xml"], default="auto")
    analysis.add_argument("--policy", type=Path)
    analysis.add_argument("--tuned", action="store_true")
    analysis.add_argument("--replay-count", type=int)
    analysis.add_argument("--output", type=Path)
    validation = commands.add_parser("validate")
    validation.add_argument("--output", type=Path)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8894)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from .server import serve_local
            serve_local(args.port)
            return 0
        if args.command == "validate":
            report = compare_policies()
            status = int(report["tuned"]["totals"]["fp"] > 0 or report["tuned"]["totals"]["fn"] > 0)
        else:
            if args.policy and args.tuned:
                raise InputError("Choose --policy or --tuned, not both.")
            policy = strict_json(read_local(args.policy)) if args.policy else tuned_policy() if args.tuned else None
            report = analyze_bytes(read_local(args.file), format=args.format, policy=policy, replay_count=args.replay_count)
            status = int(report["alert_count"] > 0)
        output = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
        if args.output:
            write_new(args.output, output)
        else:
            print(output, end="")
        return status
    except (InputError, OSError) as exc:
        message = str(exc) if isinstance(exc, InputError) else type(exc).__name__
        print("Lab error: " + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
