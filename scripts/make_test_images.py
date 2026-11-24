#!/usr/bin/env python3
"""Generate Evidentia test disk images with known deleted, fragmented and corrupted files.

    python scripts/make_test_images.py [output_dir]     (default: ./test_images)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from evidentia.testdata.generator import generate  # noqa: E402

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test_images"
    meta = generate(out)
    for k, v in meta["images"].items():
        print(f"  {k:9s} {v}  ({os.path.getsize(v) / 2**20:.0f} MiB)")
    for n in meta["notes"]:
        print("  note:", n)
    states = {}
    for f in meta["files"]:
        states[f["state"]] = states.get(f["state"], 0) + 1
    print(f"  {len(meta['files'])} planted files:", ", ".join(f"{k}={v}" for k, v in sorted(states.items())))
    print(f"  ground truth: {os.path.join(out, 'manifest.json')}")
