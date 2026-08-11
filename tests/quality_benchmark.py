#!/usr/bin/env python3
"""Cross-platform decompiler quality benchmark.

The manifest is intentionally extensible: CI or a local large-corpus job can
replace it with Linux ELF and Windows PE applications without changing the
runner. Results are stable JSON suitable for baseline comparison/artifacts.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time


parser = argparse.ArgumentParser()
parser.add_argument("--centrifuge", required=True)
parser.add_argument("--source-dir", required=True)
parser.add_argument("--manifest", required=True)
parser.add_argument("--output")
parser.add_argument("--baseline")
parser.add_argument("--timeout", type=float, default=120.0)
args = parser.parse_args()

root = Path(args.source_dir).resolve()
executable = Path(args.centrifuge).resolve()
manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))


def run(command):
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace",
                                   timeout=args.timeout)
    except subprocess.TimeoutExpired as error:
        completed = subprocess.CompletedProcess(
            command, 124, error.stdout or "", error.stderr or "timeout")
    return completed, time.perf_counter() - started


cases = list(manifest.get("cases", []))
for corpus in manifest.get("corpora", []):
    matches = sorted(root.glob(corpus["glob"]))
    maximum = int(corpus.get("max_binaries", len(matches)))
    for binary_path in matches[:maximum]:
        cases.append({
            "name": f'{corpus["name"]}:{binary_path.name}',
            "binary": binary_path.relative_to(root).as_posix(),
            "spec": corpus["spec"],
            "abi": corpus.get("abi", ""),
            "functions": corpus.get("functions", []),
            "minimum_typed_characters": corpus.get(
                "minimum_typed_characters", 0),
            "maximum_empty_semantics": corpus.get(
                "maximum_empty_semantics", 0),
            "maximum_decode_failures": corpus.get(
                "maximum_decode_failures", 0),
        })

baseline_cases = {}
if args.baseline:
    baseline_report = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    baseline_cases = {case["name"]: case
                      for case in baseline_report.get("cases", [])}

report = {"schema": 2, "cases": [], "passed": True}
coverage_pattern = re.compile(
    r"semantic coverage: ([0-9.]+)% bytes \(([0-9]+) instructions, "
    r"([0-9]+) decode failures, ([0-9]+) empty semantics, "
    r"([0-9]+) unimplemented operations\)")
for case in cases:
    binary = root / case["binary"]
    spec = root / case["spec"]
    prefix = [str(executable), "spec", str(spec), str(binary)]
    entry = {
        "name": case["name"],
        "binary": case["binary"],
        "platform": "windows" if binary.suffix.lower() in (".exe", ".dll")
                    else "linux",
        "functions": [],
    }
    analysis, analysis_time = run(prefix + ["analyze-all", case.get("abi", "")])
    entry["analysis_seconds"] = round(analysis_time, 6)
    entry["analysis_ok"] = analysis.returncode == 0
    entry["analyzed_function_lines"] = sum(" @ 0x" in line
                                             for line in analysis.stdout.splitlines())
    coverage, coverage_time = run(prefix + ["semantic-coverage"])
    entry["coverage_seconds"] = round(coverage_time, 6)
    entry["coverage_summary"] = coverage.stdout.splitlines()[0] \
        if coverage.stdout.splitlines() else ""
    coverage_match = coverage_pattern.search(entry["coverage_summary"])
    entry["byte_coverage_percent"] = float(coverage_match.group(1)) \
        if coverage_match else 0.0
    entry["decode_failures"] = int(coverage_match.group(3)) \
        if coverage_match else -1
    entry["empty_semantics"] = int(coverage_match.group(4)) \
        if coverage_match else -1
    entry["unimplemented_operations"] = int(coverage_match.group(5)) \
        if coverage_match else -1

    typed_characters = 0
    unresolved = 0
    gotos = 0
    for address in case.get("functions", []):
        decompiled, elapsed = run(prefix + ["decompile-typed", address,
                                             case.get("abi", "")])
        text = decompiled.stdout
        typed_characters += len(text)
        unresolved += text.count("UNIMPLEMENTED") + text.count("/* call ")
        gotos += text.count("goto ")
        entry["functions"].append({
            "address": address,
            "ok": decompiled.returncode == 0,
            "seconds": round(elapsed, 6),
            "characters": len(text),
            "gotos": text.count("goto "),
            "unresolved": text.count("UNIMPLEMENTED") + text.count("/* call "),
        })
    entry["typed_characters"] = typed_characters
    entry["unresolved_markers"] = unresolved
    entry["gotos"] = gotos
    minimum = int(case.get("minimum_typed_characters", 0))
    maximum_empty = int(case.get("maximum_empty_semantics", 0))
    maximum_decode = int(case.get("maximum_decode_failures", 0))
    entry["passed"] = (entry["analysis_ok"] and
                       coverage.returncode == 0 and coverage_match is not None and
                       entry["empty_semantics"] <= maximum_empty and
                       entry["decode_failures"] <= maximum_decode and
                       all(function["ok"] for function in entry["functions"]) and
                       typed_characters >= minimum and unresolved == 0)
    baseline = baseline_cases.get(case["name"])
    entry["baseline_regression"] = False
    if baseline:
        entry["baseline_regression"] = (
            typed_characters < int(baseline.get("typed_characters", 0)) or
            unresolved > int(baseline.get("unresolved_markers", 0)) or
            entry["empty_semantics"] > int(
                baseline.get("empty_semantics", maximum_empty)) or
            entry["decode_failures"] > int(
                baseline.get("decode_failures", maximum_decode)))
        entry["passed"] = entry["passed"] and not entry["baseline_regression"]
    report["passed"] = report["passed"] and entry["passed"]
    report["cases"].append(entry)

rendered = json.dumps(report, indent=2, sort_keys=True)
if args.output:
    Path(args.output).write_text(rendered + "\n", encoding="utf-8")
print(rendered)
sys.exit(0 if report["passed"] else 1)
