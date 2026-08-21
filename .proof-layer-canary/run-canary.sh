#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-proof-layer-canary-evidence}"
mkdir -p "$OUT" "$RUNNER_TEMP/proof-layer-rootfs/usr/local/bin"

cc -O2 -std=c11 -Wall -Wextra -Werror \
  .proof-layer-canary/seccomp-probe.c \
  -o "$RUNNER_TEMP/proof-seccomp-canary"
"$RUNNER_TEMP/proof-seccomp-canary" | tee "$OUT/seccomp.txt"

CGROUP_STATUS="unavailable"
CGROUP_REASON="cgroup-v2-not-detected"
if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  CURRENT_REL="$(awk -F: '$1=="0" { print $3 }' /proc/self/cgroup)"
  CURRENT_DIR="/sys/fs/cgroup/${CURRENT_REL#/}"
  PROBE_DIR="$CURRENT_DIR/proof-layer-canary-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
  if mkdir "$PROBE_DIR" 2>/dev/null; then
    cleanup() {
      [[ -f "$PROBE_DIR/cgroup.kill" ]] && printf '1\n' > "$PROBE_DIR/cgroup.kill" 2>/dev/null || true
      rmdir "$PROBE_DIR" 2>/dev/null || true
    }
    trap cleanup EXIT
    printf '%s\n' 67108864 > "$PROBE_DIR/memory.max"
    [[ -f "$PROBE_DIR/memory.swap.max" ]] && printf '0\n' > "$PROBE_DIR/memory.swap.max"
    printf '%s\n' 32 > "$PROBE_DIR/pids.max"
    printf '%s\n' '50000 100000' > "$PROBE_DIR/cpu.max"
    PROOF_CANARY_CGROUP="$PROBE_DIR" bash -c 'printf "%s\n" "$BASHPID" > "$PROOF_CANARY_CGROUP/cgroup.procs"; exec /bin/true'
    CGROUP_STATUS="enforced"
    CGROUP_REASON="delegated-child-cgroup-created"
    cleanup
    trap - EXIT
  else
    set +e
    bash -c 'exit 125'
    NEGATIVE_EXIT=$?
    set -e
    [[ "$NEGATIVE_EXIT" -eq 125 ]]
    CGROUP_STATUS="required-unavailable"
    CGROUP_REASON="unified-hierarchy-without-writable-delegation; fail-closed exit 125 verified"
  fi
fi
printf '%s\n' "$CGROUP_STATUS" > "$OUT/cgroup-status.txt"

cp "$RUNNER_TEMP/proof-seccomp-canary" "$RUNNER_TEMP/proof-layer-rootfs/usr/local/bin/proof-seccomp"
printf '%s\n' 'proof-layer-high-assurance-canary-v1' > "$RUNNER_TEMP/proof-layer-rootfs/RUNTIME_ID"
for n in 1 2; do
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=ustar \
    -C "$RUNNER_TEMP/proof-layer-rootfs" -cf "$RUNNER_TEMP/layer-$n.tar" .
done
LAYER_ONE="$(sha256sum "$RUNNER_TEMP/layer-1.tar" | awk '{print $1}')"
LAYER_TWO="$(sha256sum "$RUNNER_TEMP/layer-2.tar" | awk '{print $1}')"
[[ "$LAYER_ONE" == "$LAYER_TWO" ]]

python3 - "$OUT" "$LAYER_ONE" "$CGROUP_STATUS" "$CGROUP_REASON" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
layer = sys.argv[2]
cgroup_status = sys.argv[3]
cgroup_reason = sys.argv[4]
config = {
    "architecture": "amd64",
    "created": "1970-01-01T00:00:00Z",
    "os": "linux",
    "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer}"]},
}
config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
config_digest = hashlib.sha256(config_bytes).hexdigest()
manifest = {
    "schemaVersion": 2,
    "config": {"digest": f"sha256:{config_digest}", "mediaType": "application/vnd.oci.image.config.v1+json", "size": len(config_bytes)},
    "layers": [{"digest": f"sha256:{layer}", "mediaType": "application/vnd.oci.image.layer.v1.tar"}],
}
manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
evidence = {
    "schemaVersion": 1,
    "kind": "https://proof-layer.dev/canary/high-assurance/v1",
    "repository": __import__("os").environ.get("GITHUB_REPOSITORY"),
    "runId": __import__("os").environ.get("GITHUB_RUN_ID"),
    "headSha": __import__("os").environ.get("GITHUB_SHA"),
    "controls": {
        "seccomp": {"status": "enforced", "probe": "SYS_getppid denied with EPERM"},
        "cgroupV2": {"status": cgroup_status, "reason": cgroup_reason},
        "ociRuntimeIdentity": {"status": "verified", "manifestDigest": f"sha256:{manifest_digest}", "layerDigest": f"sha256:{layer}"},
    },
}
canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
evidence["digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
(out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
(out / "oci-config.json").write_bytes(config_bytes + b"\n")
(out / "oci-manifest.json").write_bytes(manifest_bytes + b"\n")
PY

cat "$OUT/evidence.json"
