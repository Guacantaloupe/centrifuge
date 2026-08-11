#!/usr/bin/env python3
"""Generate and compile a complete recovered PE64 C++ project."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument("--centrifuge", required=True)
parser.add_argument("--source-dir", required=True)
parser.add_argument("--cmake", required=True)
args = parser.parse_args()

root = Path(args.source_dir).resolve()
centrifuge = Path(args.centrifuge).resolve()
with tempfile.TemporaryDirectory(prefix="centrifuge-project-") as temporary:
    output = Path(temporary) / "recovered"
    command = [
        str(centrifuge), "spec", str(root / "sleigh" / "x86-64.slaspec"),
        str(root / "samples" / "sample_pe64.exe"), "recover-project",
        str(output), "win64",
    ]
    recovered = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", check=True)
    report = json.loads((output / "recovery_report.json").read_text(
        encoding="utf-8"))
    assert report["emitted_functions"] >= 1, recovered.stdout
    assert report["stubbed_functions"] == 0, recovered.stdout
    assert report["unresolved_markers"] == 0, recovered.stdout
    assert report["data_regions"] >= 1, recovered.stdout
    assert report["entry_point"] != 0, recovered.stdout
    assert report["entry_point_recovered"], recovered.stdout
    assert (output / "data" / "globals.bin").is_file()
    assert (output / "globals.json").is_file()
    assert (output / "imports.json").is_file()
    assert (output / "resources" / "index.json").is_file()
    assert (output / "entrypoint.json").is_file()
    assert (output / "include" / "recovered_metadata.hpp").is_file()
    runtime_header = (output / "include" / "recovered_runtime.hpp").read_text(
        encoding="utf-8")
    runtime_source = (output / "src" / "recovered_runtime.cpp").read_text(
        encoding="utf-8")
    metadata_source = (output / "src" / "recovered_metadata.cpp").read_text(
        encoding="utf-8")
    assert "recovered_resolve_iat_slot(address, sizeof(T), imported)" in runtime_header
    assert "runtime_iat_slots.emplace" in runtime_source
    assert "resolve_recovered_import(slot->second)" in runtime_source
    assert "CENTRIFUGE_RUNTIME_STRICT_HEAP" in runtime_source
    assert "if (!runtime_strict_heap_bounds)" in runtime_source
    assert "Stack and heap addresses dominate recovered execution" in runtime_source
    assert "address < original_image_begin || address >= original_image_end" in runtime_source
    assert "value < original_image_begin || value >= original_image_end" in runtime_source
    assert "recovered_iat_begin" in runtime_header
    assert "if constexpr (sizeof(T) == 8)" in runtime_header
    assert "address >= recovered_iat_begin && address <= recovered_iat_end" in runtime_header
    assert "lock-free" in metadata_source
    assert "compare_exchange_strong" in metadata_source
    assert "cache_mutex" not in metadata_source
    assert "const char* source_path" in (
        output / "include" / "recovered_metadata.hpp").read_text(encoding="utf-8")
    assert "dependencies\\\\" in metadata_source
    assert "LOAD_WITH_ALTERED_SEARCH_PATH" in metadata_source
    assert "item.source_path" in metadata_source
    assert (output / "dependencies").is_dir()
    assert "address < runtime_iat_slots.begin()->first" in runtime_source
    assert "MEM_RESERVE, PAGE_NOACCESS" in runtime_source
    assert "MEM_COMMIT, PAGE_READWRITE" in runtime_source
    assert "region.mapped" in runtime_source
    assert "VirtualFree(reservation, 0, MEM_RELEASE)" in runtime_source
    assert "runtime_tls_template" in runtime_source
    assert "runtime_tls_slots[0]" in runtime_source
    assert "runtime_teb.data() + 0x58" in runtime_source
    assert "recovered_run_tls_callbacks" in runtime_source
    assert "recovered_run_tls_callbacks();" in metadata_source
    graph = json.loads((output / "knowledge_graph.json").read_text(
        encoding="utf-8"))
    assert graph["nodes"] and graph["edges"]

    build = output / "build"
    subprocess.run([args.cmake, "-S", str(output), "-B", str(build),
                    "-DCMAKE_BUILD_TYPE=Release"], check=True)
    subprocess.run([args.cmake, "--build", str(build), "--config", "Release",
                    "-j", "2"], check=True)
    candidates = [build / "recovered_verifier.exe",
                  build / "Release" / "recovered_verifier.exe",
                  build / "recovered_verifier"]
    verifier = next((candidate for candidate in candidates if candidate.exists()),
                    None)
    assert verifier is not None
    executed = subprocess.run([str(verifier)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", check=True)
    assert "Centrifuge recovered project" in executed.stdout

print("PE64 recovered project generated, compiled, linked, and executed")
