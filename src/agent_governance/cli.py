"""Local CLI. This interface deliberately exposes no live execution commands."""
import argparse
import json
from pathlib import Path
from .policy import Intent, Policy, evaluate
from .demo import run_demo, write_report


def read_json(path: Path):
    if path.stat().st_size > 1_000_000:
        raise ValueError("JSON input exceeds 1 MB")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect agent mandates using synthetic data and a local policy gate.")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("evaluate", help="Evaluate an intent without executing a tool")
    inspect.add_argument("--policy", required=True, type=Path)
    inspect.add_argument("--intent", required=True, type=Path)
    inspect.add_argument("--spent-cents", type=int, default=0)
    inspect.add_argument("--stopped", action="store_true")
    demo = commands.add_parser("demo", help="Run fixture-only scenarios and generate evidence")
    demo.add_argument("--policy", required=True, type=Path)
    demo.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        policy = Policy(read_json(args.policy))
        if args.command == "evaluate":
            decision = evaluate(policy, Intent.from_dict(read_json(args.intent)), args.spent_cents, args.stopped)
            print(json.dumps(decision.to_dict(), indent=2))
            return {"allow": 0, "review": 2, "deny": 3}[decision.outcome]
        data = run_demo(policy)
        write_report(data, args.output)
        print(json.dumps({"output": str(args.output), "summary": data["summary"], "audit_valid": data["verification"]["valid"]}, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print(json.dumps({"outcome": "error", "message": str(exc)}))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

