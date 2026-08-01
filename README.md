# CorporateHub: static baseline for an LPR desktop prototype

CorporateHub is a legacy Tkinter prototype for reviewing video files, passing
frames to DTK license-plate-recognition bindings, recording detections in
SQLite, and inspecting reports. This repository is being documented before
runtime rehabilitation.

The current entry point has **no authentication or authorization**. It launches
as a trusted-local prototype and must not be exposed as a shared or remote
service. No performance, security, accuracy, or production-readiness claim is
made. The repository does not currently grant an open-source license.

## Current evidence level

The baseline tests parse and inspect source without importing the application
or either vendor wrapper. The application has not been executed in this stage:
the required DTK native libraries and a compatible licensed runtime are not
present in this repository. There are therefore no truthful runtime screenshots
or benchmark results yet.

### Static architecture map — not runtime evidence

The diagram below is derived from imports, constructor calls, queue/thread code,
and filesystem/SQLite paths in the tracked Python source. It documents static
code relationships only; it does not prove that the application or any workflow
runs successfully.

```mermaid
flowchart LR
    Operator["Trusted local operator"] --> GUI["main.py / Tkinter MainApp"]
    GUI --> Progress["ProgressFrame"]
    GUI --> Settings["SettingsDialog"]
    GUI --> Reports["ReportPanel"]
    GUI --> Manager["VideoProcessingManager<br/>queues + worker threads"]
    GUI --> RTSPPolicy["rtsp_policy.py<br/>credential-free admission + quarantine"]
    Manager --> DB
    Manager --> RTSPPolicy
    RTSPPolicy --> Quarantine["Fixed unavailable decision<br/>no camera capture"]

    Manager --> Processor["VideoProcessor"]
    Processor --> LPRWrapper["DTKLPR5.py<br/>ctypes wrapper"]
    Processor --> VIDWrapper["DTKVID.py<br/>ctypes wrapper"]
    LPRWrapper --> VIDWrapper
    LPRWrapper -. "external boundary" .-> NativeLPR["DTK LPR native library<br/>not included"]
    VIDWrapper -. "external boundary" .-> NativeVideo["DTK Video native library<br/>not included"]

    GUI --> DB["DB / sqlite3"]
    Progress --> DB
    Settings --> DB
    Reports --> DB
    Processor --> DB
    DB --> SQLite[("plates_data.db<br/>runtime data")]
    Processor --> PathPolicy["path_policy.py<br/>component + containment policy"]
    Progress --> PathPolicy
    Reports --> PathPolicy
    PathPolicy --> Images["Project-local managed image roots"]

    Processor -. imports .-> Pillow["Pillow"]
    Processor -. imports .-> OpenCV["OpenCV"]
    Processor -. imports .-> Levenshtein["python-Levenshtein"]
    Manager -. imports .-> OpenCV
    DB -. imports .-> Levenshtein
    LPRWrapper -. imports .-> Pillow
    LPRWrapper -. imports .-> NumPy["NumPy"]
    VIDWrapper -. imports .-> Pillow
    VIDWrapper -. imports .-> NumPy
```

## Dependency and DTK boundary

There is no dependency manifest or lock file, so the current checkout does not
define reproducible package versions. Static imports show these requirements:

- Python with Tkinter and the standard-library SQLite module;
- Pillow (`PIL`), NumPy, OpenCV (`cv2`), and `python-Levenshtein`;
- the separately supplied DTK License Plate Recognition and DTK Video Capture
  native libraries, plus whatever license the vendor requires.

`DTKLPR5.py` and `DTKVID.py` are Python `ctypes` wrappers carrying DTK Software
copyright headers. They are preserved byte-for-byte in this baseline. The
runtime code currently points at `../../lib/windows/x64/`; those native
binaries are not included, and this repository does not establish that the
path is portable or correct for a given machine. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for exact wrapper hashes and
the licensing boundary.

After independently supplying compatible dependencies and DTK components, the
declared GUI entry point is:

```text
python3 main.py
```

That command is documentation of the entry point, not a verified setup recipe.
Use only a trusted local machine with non-sensitive test material until the
runtime is rehabilitated and independently reviewed.

## Static workflow

The code currently describes this intended file-video path:

1. A local operator creates or selects a profile in the Tkinter UI.
2. `VideoProcessingManager` queues selected files and starts worker threads.
3. `VideoProcessor` hands captured frames to the DTK wrappers.
4. Detection callbacks update SQLite records and write plate/frame images.
5. Report and settings panels query or update the same local database.

This sequence is a reading of the source, not runtime evidence.

## Source-verified path-containment increment

Four plate-derived image-write sites now pass filesystem components through a
standard-library-only path policy. Ordinary uppercase ASCII identifiers such
as `ABC123`, `AB-1234`, and `LV_42` retain their existing component names.
Lowercase variants receive a digest suffix so they remain distinct from
uppercase variants on case-insensitive filesystems. Components requiring
normalization, unsafe-character replacement, reserved-name handling, or
truncation also receive a stable digest suffix. The generated suffix namespace
is reserved so a crafted raw ASCII value cannot claim another input's generated
component. New writes are checked against the project-local `images/`,
`detection_history/`, or `blacklist_matches/` root, including checks for
existing symlink escapes. Raw recognition text remains in legacy database, UI,
matching/cache, and logging flows; only the new managed filenames use derived
components. Logging redaction is a later rehabilitation stage.

The folder actions no longer interpolate a database path into a shell command.
They derive a managed detection folder and pass an encoded local-file URI to
the browser integration. Exported-report opening uses the same URI encoder.
The HTML generator and its image-copy behavior have not been rewritten or
runtime-tested in this increment.

This policy is defense in depth, not a complete filesystem sandbox. It does not
eliminate filesystem races, replace OS permissions, validate legacy database
paths, or establish authorization. Existing artifacts whose names were derived
by older code are not renamed or migrated; folder actions target the new
component policy, so a legacy artifact may need manual, privacy-reviewed
handling.

## Source-verified RTSP quarantine

Live-camera capture remains unavailable, but the former broken path is now
fail-closed. The GUI does not solicit an endpoint: its RTSP control shows one
fixed unavailable explanation. `VideoProcessingManager.add_rtsp_stream()`
discards its arguments and raises a fixed error before any endpoint-dependent
queue, progress, OpenCV, database-write, processor, or DTK operation. The
ordinary video-file entry point also rejects `rtsp:` and `rtsps:` transport
prefixes, including case variants and leading ASCII controls, before queueing
or opening them.

The isolated standard-library-only `rtsp_policy` module validates a deliberately
narrow, credential-free `rtsp://host[:port]/path` shape. It rejects userinfo,
queries, fragments, controls, non-ASCII input, invalid ports and hosts, and
ambiguous paths, then discards the input and exposes only fixed public metadata.
`RtspSource` cannot be constructed through its public constructor. This parser
is a policy boundary for later work, not a camera client, and the GUI does not
currently pass an endpoint to it.

Exception messages and serialized public metadata do not embed the input.
Python tracebacks retain frame locals, however, so a caught policy traceback can
still retain its endpoint; do not persist or publish such tracebacks. The
file-entry guard is RTSP-specific, not a general URI or network sandbox. Other
network-shaped strings have not yet received an equivalent source boundary.

Do not treat RTSP as a working feature. No camera stream was opened, no native
RTSP call was made, and no live-camera lifecycle was runtime-validated in this
increment.

### Reproduce the quarantine evidence

The following artifacts are source-only evidence, not camera runtime evidence.
`rtsp_evidence.py` executes ten policy cases, checks the three entry points as
AST, hashes the four evidence-bearing sources, and renders every artifact from
that single result. It never imports the GUI, OpenCV, database, vendor wrappers,
or native runtime. The tracked outputs contain no endpoint values, host state,
timestamps, absolute paths, or commit identifiers.

```text
python3 rtsp_evidence.py
python3 rtsp_evidence.py --check
python3 rtsp_evidence.py --write
```

`--check` byte-compares all tracked outputs. `--write` refuses to publish if a
policy case or source binding fails, then replaces each artifact atomically.
The canonical receipt is available as
[`evidence/rtsp-quarantine-v1.json`](evidence/rtsp-quarantine-v1.json).

[![Exact CorporateHub RTSP quarantine CLI receipt](docs/assets/rtsp-quarantine-cli.svg)](docs/assets/rtsp-quarantine-cli.svg)

The terminal visual above is generated line-for-line from the same receipt that
the CLI prints. It reports the executed case and source-binding totals, not a
simulated application session.

[![Source-bound RTSP quarantine flow](docs/assets/rtsp-quarantine-flow.svg)](docs/assets/rtsp-quarantine-flow.svg)

The flow visual names all three verified GUI/manager surfaces and their distinct
fixed-denial behavior. Syntax admission is shown separately because the GUI is
not wired to that future-facing policy path.

[![Observed RTSP policy result matrix](docs/assets/rtsp-quarantine-matrix.svg)](docs/assets/rtsp-quarantine-matrix.svg)

The matrix is rendered from the ten observed results. `MATCH` means the expected
policy outcome was observed; capture remains denied. Inputs appear only as
non-sensitive classes, while the JSON carries stable outcome codes and full
source hashes without storing the tested endpoint values.

## Data and operational risks

The prototype can write license-plate text, timestamps, source filenames,
blacklist information, SQLite data, and cropped/full-frame images to the local
working tree. RTSP URLs can contain credentials, but the current GUI no longer
solicits them and the narrow parser rejects credential-bearing forms. Traceback
locals remain a sensitive diagnostic surface. Apart from the bounded path and
RTSP increments above, the source does not implement encryption,
authentication, authorization, retention enforcement, redaction, a complete
filesystem sandbox, or a tested deletion workflow. Logs and exported reports
can add further copies.

Use synthetic or explicitly authorized data only. Keep runtime databases,
camera media, images, logs, reports, exports, native binaries, and environment
files out of version control; the baseline `.gitignore` covers the known
locations and file classes. HTML report destinations are operator-selected;
save them outside the checkout because source HTML is intentionally not
globally ignored. See [SECURITY.md](SECURITY.md) before handling any real data.

## Source-only verification

The source-only verification suite has only Python standard-library
dependencies, invokes the Git CLI to enumerate commit candidates, and imports
the project-owned `path_policy`, `rtsp_policy`, and `rtsp_evidence` modules. That
source-only set does not import the GUI, database, vendor wrappers, or native
runtime:

```text
python3 -m unittest discover -s tests -v
```

The checks parse Python source, verify removal of the former password gate,
bind vendor notices to exact wrapper hashes, inspect ignore coverage and
tracked runtime artifacts, exercise the isolated path policy (including
traversal, Unicode, length, digest, symlink, and URI cases), bind its call sites
through AST inspection, and scan repository text for high-confidence secret
signatures. The RTSP checks exercise endpoint classification and fixed public
metadata, bind both GUI and manager denial paths through AST inspection, and
include mutations for raw display, dead runtime calls, late guards, and queue
bypasses. Evidence checks also require the JSON and three accessible SVGs to be
deterministic, current, endpoint-free, locally linked, and sensitive to source
or artifact mutations. They do not validate GUI behavior, DTK licensing,
recognition quality, native-library loading, video processing, database
concurrency, filesystem race resistance, HTML safety, or RTSP operation.

## Repository status

This is a source-only rehabilitation stage. Planned follow-up work must preserve
the vendor boundary, add reproducible dependency/runtime fixtures where
licensing permits, repair remaining behavior behind tests, and capture only
real, sanitized, reproducible visual evidence.
