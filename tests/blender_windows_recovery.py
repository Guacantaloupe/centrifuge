#!/usr/bin/env python3
"""Opt-in large Windows PE benchmark for project recovery.

This stage proves deterministic loading, whole-program analysis, C++ project
generation, recompilation, linking, and execution of the recovery verifier.
It records semantic equivalence as false until startup/render trace replay is
implemented; compilation alone is never reported as behavioral equivalence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


parser = argparse.ArgumentParser()
parser.add_argument("--centrifuge", required=True)
parser.add_argument("--source-dir", required=True)
binary_group = parser.add_mutually_exclusive_group(required=True)
binary_group.add_argument("--binary")
binary_group.add_argument("--blender", help=argparse.SUPPRESS)
parser.add_argument("--manifest", required=True)
parser.add_argument("--output-dir", required=True)
parser.add_argument("--report-name", default="blender_recovery_report.json")
parser.add_argument("--cmake", required=True)
parser.add_argument("--timeout", type=float, default=1800.0)
args = parser.parse_args()

root = Path(args.source_dir).resolve()
binary = Path(args.binary or args.blender).resolve()
output = Path(args.output_dir).resolve()
manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
output.mkdir(parents=True, exist_ok=True)

if not binary.is_file():
    raise SystemExit(f"Windows fixture does not exist: {binary}")
with binary.open("rb") as stream:
    if stream.read(2) != b"MZ":
        raise SystemExit(f"Fixture is not a Windows PE image: {binary}")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


binary_sha256 = sha256_file(binary)
expected_binary_sha256 = manifest.get("binary_sha256")
if expected_binary_sha256 and binary_sha256 != expected_binary_sha256:
    raise SystemExit(
        f"Fixture SHA-256 mismatch: expected "
        f"{expected_binary_sha256}, got {binary_sha256}")


def run(command, timeout=None):
    started = time.perf_counter()
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout or args.timeout)
    return completed, round(time.perf_counter() - started, 6)


prefix = [str(Path(args.centrifuge).resolve()), "spec",
          str(root / manifest["spec"]), str(binary)]
project = output / "project"
maximum = str(manifest.get("maximum_functions", 0))
recovered, recovery_seconds = run(
    prefix + ["recover-project", str(project), manifest.get("abi", ""), maximum])
if recovered.returncode != 0:
    raise SystemExit(recovered.stdout + recovered.stderr)

configure, configure_seconds = run([
    args.cmake, "-S", str(project), "-B", str(project / "build"),
    "-DCMAKE_BUILD_TYPE=Release",
])
build, build_seconds = run([
    args.cmake, "--build", str(project / "build"), "--config", "Release",
    "-j", "2",
]) if configure.returncode == 0 else (configure, 0.0)

candidates = [project / "build" / "recovered_verifier.exe",
              project / "build" / "Release" / "recovered_verifier.exe"]
verifier = next((candidate for candidate in candidates if candidate.exists()), None)
verified = None
verifier_seconds = 0.0
if build.returncode == 0 and verifier:
    verified, verifier_seconds = run([str(verifier)], timeout=60)

recovery_report = json.loads((project / "recovery_report.json").read_text(
    encoding="utf-8"))
report = {
    "schema": 1,
    "fixture": manifest["name"],
    "version": manifest["version"],
    "binary": str(binary),
    "binary_bytes": binary.stat().st_size,
    "binary_sha256": binary_sha256,
    "recovery_seconds": recovery_seconds,
    "configure_seconds": configure_seconds,
    "build_seconds": build_seconds,
    "verifier_seconds": verifier_seconds,
    "project_generated": recovered.returncode == 0,
    "project_compiled": build.returncode == 0,
    "verifier_executed": bool(verified and verified.returncode == 0),
    "semantic_equivalence_verified": False,
    "recovery": recovery_report,
    "stderr": (configure.stderr + build.stderr)[-16000:],
}
report["quality_thresholds_passed"] = (
    recovery_report["unresolved_markers"] <=
        int(manifest.get("maximum_unresolved_markers", 2**63 - 1)) and
    recovery_report["knowledge_nodes"] >=
        int(manifest.get("minimum_knowledge_nodes", 0)) and
    recovery_report["imported_libraries"] >=
        int(manifest.get("minimum_imported_libraries", 0)) and
    recovery_report["imported_symbols"] >=
        int(manifest.get("minimum_imported_symbols", 0)) and
    recovery_report["data_regions"] >=
        int(manifest.get("minimum_data_regions", 0)) and
    recovery_report["resources"] >=
        int(manifest.get("minimum_resources", 0)) and
    recovery_report["entry_point_recovered"] and
    (project / "data" / "globals.bin").is_file() and
    (project / "imports.json").is_file() and
    (project / "resources" / "index.json").is_file() and
    (project / "entrypoint.json").is_file()
)
(output / args.report_name).write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if report["project_compiled"] and
                 report["verifier_executed"] and
                 report["quality_thresholds_passed"] else 1)
