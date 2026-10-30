#!/usr/bin/env python3
"""Build a reproducible plugin, checksum manifest and container build context."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE
OUTPUT = ROOT / "dist"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    binary = OUTPUT / "openbao-plugin-secrets-omni"
    env = os.environ.copy()
    env.update(CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
    subprocess.run([
        "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
        "-ldflags=-s -w", "-o", str(binary), "./cmd/openbao-plugin-secrets-omni",
    ], cwd=SOURCE, env=env, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {
        "version": "v0.1.0", "command": binary.name,
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "sourceRevision": revision,
        "sourceDirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "platform": "linux/amd64", "openbao": "2.7.1", "omni": "1.12.2",
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (OUTPUT / "SHA256SUMS").write_text(manifest["sha256"] + "  " + binary.name + "\n")
    (OUTPUT / "plugin.hcl").write_text(
        'plugin "secret" "omni" {\n'
        f'  command = "{binary.name}"\n  version = "{manifest["version"]}"\n'
        f'  sha256sum = "{manifest["sha256"]}"\n'
        '}\n'
    )
    shutil.copyfile(SOURCE / "Dockerfile", OUTPUT / "Dockerfile")
    print("Built linux/amd64 Omni plugin and public verification metadata in dist/.")


if __name__ == "__main__":
    main()
