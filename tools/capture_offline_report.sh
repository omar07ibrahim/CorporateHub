#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "usage: $0" >&2
    exit 2
fi

readonly image='mcr.microsoft.com/playwright@sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c'
readonly browser='/ms-playwright/chromium_headless_shell-1193/chrome-linux/headless_shell'
readonly browser_version='Chromium 140.0.7339.186'
readonly browser_sha256='003728e0b77eb9d52e4d258594bd55ce22ecd245eb6d3b6858fbd844c901ad7d'

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
demo_root="$repo_root/docs/demo/offline-report-v1"
output_path="$repo_root/docs/assets/offline-report-browser.png"

if ! command -v docker >/dev/null 2>&1; then
    echo "capture error: Docker is required" >&2
    exit 1
fi
if [[ $(id -u) -eq 0 || $(id -g) -eq 0 ]]; then
    echo "capture error: refusing to run Chromium as root" >&2
    exit 1
fi
if [[ ! -d "$demo_root" || -L "$demo_root" ]]; then
    echo "capture error: prepare the managed synthetic demo first" >&2
    exit 1
fi
if find "$demo_root" -mindepth 1 -maxdepth 1 ! -type d -print -quit | grep -q .; then
    echo "capture error: managed demo contains an unknown entry" >&2
    exit 1
fi

mapfile -d '' bundle_roots < <(
    find "$demo_root" -mindepth 1 -maxdepth 1 -type d -print0
)
if [[ ${#bundle_roots[@]} -ne 1 ]]; then
    echo "capture error: expected exactly one synthetic report bundle" >&2
    exit 1
fi
bundle_root=${bundle_roots[0]}
bundle_name=$(basename -- "$bundle_root")
if [[ ! "$bundle_name" =~ ^corporatehub-report-[0-9a-f]{64}$ ]]; then
    echo "capture error: synthetic report bundle name is invalid" >&2
    exit 1
fi
index_path="$bundle_root/index.html"
if [[ ! -f "$index_path" || -L "$index_path" ]]; then
    echo "capture error: synthetic report index is invalid" >&2
    exit 1
fi
output_parent=$(dirname -- "$output_path")
for managed_path in \
    "$repo_root/docs" \
    "$repo_root/docs/demo" \
    "$demo_root" \
    "$bundle_root" \
    "$index_path" \
    "$output_parent"; do
    if [[ $(realpath -e -- "$managed_path") != "$managed_path" ]]; then
        echo "capture error: managed evidence path contains a symlink" >&2
        exit 1
    fi
done
if [[ -L "$output_path" || ( -e "$output_path" && ! -f "$output_path" ) ]]; then
    echo "capture error: screenshot destination is unsafe" >&2
    exit 1
fi
if [[ -e "$output_path" && $(stat -c '%h' -- "$output_path") -ne 1 ]]; then
    echo "capture error: screenshot destination has multiple hard links" >&2
    exit 1
fi

canonical_relative=$(python3 -B "$repo_root/report_evidence.py" --demo-index)
canonical_index="$repo_root/$canonical_relative"
if [[ "$index_path" != "$canonical_index" ]]; then
    echo "capture error: managed bundle is not the fixed canonical fixture" >&2
    exit 1
fi

python3 -B "$repo_root/report_export.py" verify "$bundle_root" >/dev/null

observed_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")
if [[ "$observed_digest" != "$image" ]]; then
    echo "capture error: cached container digest is not exact" >&2
    exit 1
fi
observed_architecture=$(docker image inspect --format '{{.Architecture}}' "$image")
if [[ "$observed_architecture" != "amd64" ]]; then
    echo "capture error: cached container architecture is not amd64" >&2
    exit 1
fi

uid=$(id -u)
gid=$(id -g)
readonly uid
readonly gid
common=(
    --rm
    --pull=never
    --platform linux/amd64
    --network none
    --user "$uid:$gid"
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --pids-limit 256
    --memory 768m
    --memory-swap 768m
    --cpus 1
    --ulimit nofile=1024:1024
    --ulimit core=0:0
    --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777'
    --tmpfs '/dev/shm:rw,nosuid,nodev,noexec,size=256m,mode=1777'
    --env HOME=/tmp
    --env XDG_CACHE_HOME=/tmp/cache
    --env XDG_CONFIG_HOME=/tmp/config
    --env LANG=C.UTF-8
    --env LC_ALL=C.UTF-8
    --env TZ=UTC
)

observed_hash=$(docker run "${common[@]}" --entrypoint /usr/bin/sha256sum \
    "$image" "$browser" | awk '{print $1}')
if [[ "$observed_hash" != "$browser_sha256" ]]; then
    echo "capture error: Chromium binary hash is not exact" >&2
    exit 1
fi
observed_version=$(docker run "${common[@]}" --entrypoint "$browser" \
    "$image" --version)
if [[ "$observed_version" != "$browser_version" ]]; then
    echo "capture error: Chromium version is not exact" >&2
    exit 1
fi

temporary_root=$(mktemp -d "$repo_root/.offline-report-capture.XXXXXX")
cidfile="$temporary_root/container.cid"
cleanup() {
    if [[ -f "$cidfile" && ! -L "$cidfile" ]]; then
        container_id=$(<"$cidfile")
        if [[ "$container_id" =~ ^[0-9a-f]{64}$ ]]; then
            docker rm -f "$container_id" >/dev/null 2>&1 || true
        fi
    fi
    if [[ -d "$temporary_root" ]]; then
        find "$temporary_root" -depth -delete
    fi
}
trap cleanup EXIT INT TERM
mkdir "$temporary_root/output"
dom_path="$temporary_root/rendered-dom.html"
capture_log="$temporary_root/capture.stderr"

capture=(
    docker run
    "${common[@]}"
    --cidfile "$cidfile"
    --mount "type=bind,src=$bundle_root,dst=/demo,readonly"
    --mount "type=bind,src=$temporary_root/output,dst=/output"
    --workdir /demo
    --entrypoint "$browser"
    "$image"
    --headless
    --no-sandbox
    --disable-background-networking
    --disable-breakpad
    --disable-component-update
    --disable-default-apps
    --disable-extensions
    '--disable-features=OptimizationHints,Translate'
    --disable-sync
    --force-color-profile=srgb
    --force-device-scale-factor=1
    --hide-scrollbars
    '--host-resolver-rules=MAP * ~NOTFOUND'
    --lang=en-US
    --metrics-recording-only
    --no-first-run
    --no-pings
    --password-store=basic
    --run-all-compositor-stages-before-draw
    --safebrowsing-disable-auto-update
    --virtual-time-budget=1000
    '--window-size=1440,2200'
    --dump-dom
    --screenshot=/output/offline-report-browser.png
    file:///demo/index.html
)

if ! timeout --signal=TERM --kill-after=5s 45s \
    "${capture[@]}" >"$dom_path" 2>"$capture_log"; then
    echo "capture error: isolated Chromium capture failed" >&2
    sed -n '1,12p' "$capture_log" >&2
    exit 1
fi

python3 -B "$repo_root/report_export.py" verify "$bundle_root" >/dev/null

python3 - "$dom_path" "$temporary_root/output" <<'PY'
from pathlib import Path
import sys

dom_path = Path(sys.argv[1])
output = Path(sys.argv[2])
dom = dom_path.read_text(encoding="utf-8")
required = (
    '<main ',
    'data-blacklisted-records="2"',
    'data-observation-records="9"',
    'data-plate-records="4"',
    'data-privacy-mode="redacted-v1"',
    'CorporateHub redacted offline report',
)
if not all(marker in dom for marker in required):
    raise SystemExit("capture error: rendered DOM sentinels are incomplete")
if "file:///" in dom or "/home/" in dom or "ERR_FILE" in dom:
    raise SystemExit("capture error: rendered DOM exposes host state or an error page")
entries = list(output.iterdir())
expected = output / "offline-report-browser.png"
if entries != [expected] or not expected.is_file() or expected.is_symlink():
    raise SystemExit("capture error: browser output inventory is invalid")
PY

python3 - "$temporary_root/output/offline-report-browser.png" <<'PY'
from pathlib import Path
import struct
import sys

content = Path(sys.argv[1]).read_bytes()
if not content.startswith(b"\x89PNG\r\n\x1a\n") or len(content) < 33:
    raise SystemExit("capture error: browser output is not PNG")
width, height = struct.unpack(">II", content[16:24])
if (width, height) != (1440, 2200):
    raise SystemExit(
        f"capture error: expected 1440x2200, observed {width}x{height}"
    )
PY

chmod 0644 "$temporary_root/output/offline-report-browser.png"
mv -f -- "$temporary_root/output/offline-report-browser.png" "$output_path"
sha256sum "$output_path"
