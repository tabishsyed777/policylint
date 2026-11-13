#!/usr/bin/env python3
"""Review authorized IAM-style JSON for broad allow statements."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def items(value):
    if value is None: return []
    if not isinstance(value, list): value = [value]
    out = []
    for item in value:
        if isinstance(item, str): out.append(item)
        elif isinstance(item, dict):
            for nested in item.values(): out.extend(items(nested))
    return out


def lint(text):
    try: policy = json.loads(text)
    except json.JSONDecodeError as error: return {"error": f"The policy is not valid JSON: {error.msg}."}
    statements = policy.get("Statement", [])
    if not isinstance(statements, list): statements = [statements]
    if not statements: return {"error": "No Statement array was found in this policy."}
    findings = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict): continue
        label = statement.get("Sid") or f"Statement {index + 1}"; effect = str(statement.get("Effect", "")).lower(); actions = [value.lower() for value in items(statement.get("Action"))]; resources = items(statement.get("Resource")); principals = items(statement.get("Principal")); condition = bool(statement.get("Condition"))
        def add(severity, title, detail, fix): findings.append({"severity": severity, "title": title, "detail": f"{label}: {detail}", "fix": fix})
        if effect != "allow": continue
        if "*" in principals: add("critical", "Public principal", "This allow statement accepts a wildcard principal.", "Name the trusted principal or add an explicit trust boundary.")
        if any(action == "*" or action.endswith(":*") for action in actions): add("high", "Wildcard action", "This statement grants an entire service or all actions.", "List only the API actions this workload needs.")
        if any(action == "iam:passrole" or re.match(r"^(iam|kms|organizations|account):\*$", action) for action in actions): add("critical", "Control-plane privilege", "This statement can change identity, key, or account administration.", "Separate administration from runtime roles and constrain the exact verbs.")
        if "*" in resources: add("high", "Wildcard resource", "This statement applies across every resource in scope.", "Use resource ARNs or IDs for the workload boundary.")
        if ("*" in principals or any(action == "*" or action.endswith(":*") for action in actions) or "*" in resources) and not condition: add("review", "Missing condition boundary", "A broad allow has no condition to narrow when or how it can be used.", "Add conditions such as source identity, tags, network, or time where supported.")
    critical = sum(item["severity"] == "critical" for item in findings); high = sum(item["severity"] == "high" for item in findings); review = sum(item["severity"] == "review" for item in findings); score = max(0, 100 - critical * 25 - high * 15 - review * 7)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "statements": len(statements), "summary": {"score": score, "critical": critical, "high": high, "review": review, "findings": len(findings)}, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("input", type=Path, help="authorized policy JSON file"); parser.add_argument("--output", type=Path, help="write JSON report to this path"); args = parser.parse_args()
    if not args.input.is_file(): parser.error(f"input file does not exist: {args.input}")
    report = lint(args.input.read_text(encoding="utf-8", errors="replace")); rendered = json.dumps(report, indent=2) + "\n"
    if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(rendered, encoding="utf-8"); print(f"Report written to {args.output}")
    else: print(rendered, end="")


if __name__ == "__main__": main()
