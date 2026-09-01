#!/usr/bin/env python3
"""foundri-publish: publish security-audit output to Foundri.

Commands:
  push <path-to-report.json>  Validate the report and POST it to FOUNDRI_INGEST_URL.
  tail                        Follow the hook-event JSONL sink and POST new lines
                              to FOUNDRI_EVENTS_URL.

Config comes from the environment:
  FOUNDRI_INGEST_URL   Ingest endpoint for audit reports (push).
  FOUNDRI_EVENTS_URL   Ingest endpoint for hook events (tail).
  FOUNDRI_TOKEN        Per-project bearer token.
  FOUNDRI_HOOK_LOG     Hook-event sink path (tail). Default ~/.foundri/hook-events.jsonl.

Stdlib only; requires Python 3.9+.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

SEVERITIES = {"critical", "high", "medium", "low", "info"}
MODULES = {
    "phi-pii", "owasp-top10", "secrets-audit", "tenant-isolation",
    "audit-trail", "pqc-crypto", "fdcpa-tcpa", "hitrust-csf",
}
FRAMEWORKS = {"hipaa", "soc2", "owasp", "hitrust", "fdcpa_tcpa", "pqc"}
CONTROL_STATUSES = {"pass", "fail", "warn"}

REQUIRED_TOP_LEVEL = [
    "report_format_version", "plugin_version", "project", "run",
    "summary", "findings", "control_results",
]


def default_hook_log_path() -> str:
    override = os.environ.get("FOUNDRI_HOOK_LOG")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~"), ".foundri", "hook-events.jsonl")


def validate_report(report) -> list:
    """Lightweight structural validation against the pinned v1 contract.

    Returns a list of human-readable errors; empty means valid. The JSON
    Schema in plugins/security-audit/schema/report.schema.json remains the
    source of truth — this is the pre-flight check before publishing.
    """
    errors = []
    if not isinstance(report, dict):
        return ["report is not a JSON object"]
    if report.get("report_format_version") != 1:
        errors.append("report_format_version must be the integer 1")
    for key in REQUIRED_TOP_LEVEL:
        if key not in report:
            errors.append(f"missing required key: {key}")
    if errors:
        return errors

    summary = report.get("summary")
    if not isinstance(summary, dict) or set(summary) != SEVERITIES:
        errors.append("summary must contain exactly: critical, high, medium, low, info")
    elif not all(isinstance(summary[k], int) and summary[k] >= 0 for k in SEVERITIES):
        errors.append("summary counts must be non-negative integers")
    else:
        # Foundri stores this tally as sent rather than deriving it from the
        # rows it inserts. A report whose summary disagrees with its own
        # findings therefore publishes numbers nothing downstream can correct,
        # so refuse it here at the producer.
        findings = report.get("findings")
        if isinstance(findings, list):
            tally = dict.fromkeys(SEVERITIES, 0)
            for finding in findings:
                if isinstance(finding, dict):
                    severity = finding.get("severity")
                    if severity in tally:
                        tally[severity] += 1
            if tally != summary:
                mismatched = ", ".join(
                    f"{key}: summary={summary[key]} findings={tally[key]}"
                    for key in sorted(SEVERITIES)
                    if summary[key] != tally[key]
                )
                errors.append(f"summary does not match the findings it ships ({mismatched})")

    for i, finding in enumerate(report.get("findings") or []):
        where = f"findings[{i}]"
        if not isinstance(finding, dict):
            errors.append(f"{where} is not an object")
            continue
        if finding.get("severity") not in SEVERITIES:
            errors.append(f"{where}.severity must be one of {sorted(SEVERITIES)}")
        if finding.get("module") not in MODULES:
            errors.append(f"{where}.module must be one of {sorted(MODULES)}")
        frameworks = finding.get("frameworks")
        if not isinstance(frameworks, list) or not set(frameworks) <= FRAMEWORKS:
            errors.append(f"{where}.frameworks must be a list from {sorted(FRAMEWORKS)}")
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict) or "snippet_redacted" not in evidence or "match" not in evidence:
            errors.append(f"{where}.evidence must contain snippet_redacted and match")

    for i, control in enumerate(report.get("control_results") or []):
        where = f"control_results[{i}]"
        if not isinstance(control, dict):
            errors.append(f"{where} is not an object")
            continue
        if control.get("framework") not in FRAMEWORKS:
            errors.append(f"{where}.framework must be one of {sorted(FRAMEWORKS)}")
        if control.get("status") not in CONTROL_STATUSES:
            errors.append(f"{where}.status must be one of {sorted(CONTROL_STATUSES)}")

    return errors


def _post_json(url: str, token: str, payload: bytes):
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "foundri-publish/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return 0, f"connection failed: {exc}"


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(f"error: {name} is not set", file=sys.stderr)
        sys.exit(2)
    return value


def cmd_push(args) -> int:
    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read {args.report}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: {args.report} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    errors = validate_report(report)
    if errors:
        print(f"error: {args.report} failed validation:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    url = _require_env("FOUNDRI_INGEST_URL")
    token = _require_env("FOUNDRI_TOKEN")

    status, body = _post_json(url, token, json.dumps(report).encode("utf-8"))
    summary = body.strip().replace("\n", " ")[:500]
    print(f"POST {url} -> {status}")
    if summary:
        print(f"response: {summary}")
    if 200 <= status < 300:
        findings = report.get("findings") or []
        counts = report.get("summary") or {}
        print(
            "published report: "
            f"{len(findings)} findings "
            f"(critical={counts.get('critical')}, high={counts.get('high')}, "
            f"medium={counts.get('medium')}, low={counts.get('low')}, info={counts.get('info')})"
        )
        return 0
    print("error: ingest endpoint returned a non-2xx status", file=sys.stderr)
    return 1


def cmd_tail(args) -> int:
    url = _require_env("FOUNDRI_EVENTS_URL")
    token = _require_env("FOUNDRI_TOKEN")
    path = args.path or default_hook_log_path()

    if not os.path.exists(path):
        if args.once:
            print(f"no hook-event sink at {path}; nothing to send")
            return 0
        print(f"waiting for hook-event sink at {path} ...", file=sys.stderr)
        while not os.path.exists(path):
            time.sleep(args.interval)

    sent = 0
    with open(path, encoding="utf-8") as fh:
        if not args.from_start:
            fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                if args.once:
                    break
                time.sleep(args.interval)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError:
                print("skipping malformed line in hook-event sink", file=sys.stderr)
                continue
            status, body = _post_json(url, token, line.encode("utf-8"))
            if not 200 <= status < 300:
                print(f"POST {url} -> {status}: {body.strip()[:300]}", file=sys.stderr)
                print("error: events endpoint returned a non-2xx status", file=sys.stderr)
                return 1
            sent += 1
    print(f"sent {sent} hook event(s) to {url}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="foundri-publish", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_push = sub.add_parser("push", help="validate and POST a report.json to FOUNDRI_INGEST_URL")
    p_push.add_argument("report", help="path to the audit report JSON")
    p_push.set_defaults(func=cmd_push)

    p_tail = sub.add_parser("tail", help="follow the hook-event JSONL and POST new lines to FOUNDRI_EVENTS_URL")
    p_tail.add_argument("--path", help="override the sink path (default: FOUNDRI_HOOK_LOG or ~/.foundri/hook-events.jsonl)")
    p_tail.add_argument("--from-start", action="store_true", help="replay the whole file instead of only new lines")
    p_tail.add_argument("--once", action="store_true", help="send available lines and exit (do not follow)")
    p_tail.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds (default 1.0)")
    p_tail.set_defaults(func=cmd_tail)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
