# Security policy

## Current status

CorporateHub is a trusted-local legacy prototype. It has no authentication or
authorization boundary and has not been validated for production, shared-host,
remote-service, or live-camera use. There is no supported release at this
stage.

Do not use the current code with live camera feeds, operational blacklists, or
personal data. Use synthetic or explicitly authorized test data while the
runtime is being rehabilitated.

## Sensitive data handled by the source

Static inspection shows code paths for license-plate text, timestamps, source
filenames, RTSP URLs, blacklist records, SQLite databases, logs, reports, and
cropped or full-frame images. RTSP URLs can embed credentials. The source does
not currently implement encryption, authentication, authorization,
general-purpose redaction outside the narrow offline-report boundary, retention
enforcement, or a verified deletion workflow.

Keep all operator/runtime-generated data outside version control and restrict
filesystem access at the operating-system boundary. The only report exception
is the fixed, generator-owned synthetic evidence under
`docs/demo/offline-report-v1`, `docs/assets`, and `evidence`; it accepts no
operator database. Do not include credentials in RTSP URLs used for development
evidence. Review images and reports for personal data before sharing them.

## RTSP quarantine and diagnostic limits

The current GUI does not solicit or retain an RTSP endpoint and does not start a
camera. Direct RTSP manager calls return a fixed unavailable error before
endpoint-dependent work. The legacy video-file entry also rejects `rtsp:` and
`rtsps:` prefixes before queue mutation or OpenCV. A standard-library parser is
available only as a credential-free policy boundary; it rejects userinfo,
queries, fragments, controls, ambiguous paths, and malformed hosts or ports,
then discards the endpoint.

This boundary is RTSP-specific, not a general URI or network sandbox. Exception
messages and allowlisted metadata omit the input, but Python tracebacks retain
frame locals and can therefore retain a rejected endpoint. Do not log, persist,
attach, or publish those tracebacks if a caller supplies sensitive input. No
camera, DTK live-capture method, timeout, lifecycle, backpressure, or native
cleanup behavior was validated by the source-only tests.

Public RTSP evidence must be generated only through `rtsp_evidence.py`; never
substitute a real camera URL or operational hostname into a tracked artifact.
The generator records input classes and stable decision codes, not fixture
values, and refuses to write when a policy case or source binding fails. Its
tracked JSON and SVG outputs are deterministic source evidence. They do not
provide credential storage, secure memory erasure, traceback redaction,
legacy-log cleanup, network isolation, TLS validation, interoperability,
reconnect behavior, timeouts, backpressure, GUI-thread handoff, performance, or
a supported camera feature.

## Bounded path-policy coverage

New files created by the four plate-derived image-write sites use a bounded
ASCII component policy and are checked against one of three project-local
managed roots: `images/`, `detection_history/`, or `blacklist_matches/`.
Uppercase ASCII plate components remain unchanged. Lowercase/case variants,
unsafe or normalized values, reserved names, overlong values, and raw values
that resemble a generated digest-suffixed name receive a digest suffix. This
avoids ordinary case-fold and raw/generated-namespace collisions, subject to
the collision resistance of the truncated SHA-256 digest. Existing symlink
escapes are rejected. Detection-folder actions derive that managed path instead
of executing a shell command, and both folder and exported report opening use
encoded local-file URIs.

Raw recognition text remains in legacy database, UI, matching/cache, and
logging flows; only the new managed filenames use derived components. Logging
redaction is a later rehabilitation stage.

This is a source-verified, defense-in-depth increment, not a complete filesystem
sandbox or authorization boundary. Filesystem changes after validation can
still race later operations. Other legacy UI, database, and logging paths have
not received equivalent review; the separate offline exporter has the narrower
boundary below.

## Redacted offline-report boundary

`report_export.py` replaces the former active HTML/image-copy generator. It
opens the application database with SQLite URI `mode=ro`, enables
`query_only`, denies write/DDL/attach operations through an authorizer, and
materializes the required rows inside one transaction. Python 3.11+ is required:
the exporter fails closed unless the runtime exposes `SQLITE_LIMIT_LENGTH` and
sets the configured per-row/value bound before reading source rows. SQL
projections also carry storage-class tags so dynamic BLOB or text values cannot
masquerade as booleans, identifiers, or confidence values. Order-independent
`math.fsum` aggregation keeps equal confidence multisets deterministic across
supported Python versions. It does not construct the mutable `DB` wrapper or
call similarity/tracking analysis. The source must be an existing regular,
non-symlink SQLite file with the declared `plates` and `plate_detections`
columns and bounded row counts.

Version-one bundles are always `redacted-v1`. Queries do not select plate text,
profiles, source filenames, blacklist reasons, timestamps, or image paths. The
public output contains report-local record labels, observed-row counts,
blacklist booleans, and bounded confidence aggregates. It copies no source
images because a standard-library byte copy cannot validate pixels or strip
metadata. Redacted aggregates can still enable re-identification; they are not
an anonymity guarantee or authorization decision. Review every bundle before
sharing.

Each immutable bundle contains one static HTML file, one canonical JSON
manifest, and one generator-owned content-addressed SVG. Verification rejects
scripts, inline event handlers, network and scheme URLs, forms, active SVG
content, unexpected paths, symlinks, non-regular files, stale hashes, and
manifest/report-ID mismatches. The manifest's typed, redacted record model is
cross-checked against summary totals; both HTML and SVG must equal a byte-exact
regeneration from that model. A pre-parse complexity scan bounds JSON structure,
and exact byte comparison rejects forged HTML/SVG before active-content parsers
run. Publishing uses a private sibling staging directory, exclusive file
creation, file `fsync`, supported directory `fsync`, verification, then a
same-parent rename. Real directory-I/O failures abort before rename. A failure
after rename is surfaced as a fixed durability warning because the verified
bundle is already published. An exact existing bundle is reused only after
verification; stale or tampered output is never overwritten.

The operator-selected output parent remains trusted. Validation is path-based,
not descriptor-relative, so a same-user adversary can race parent-directory
changes between checks. Content addressing and exact regeneration do not prove
authorship, source-database provenance, or truth of the aggregates; a trusted
expected report ID or external signature is required for provenance. The bundle
is not encrypted, signed, access-controlled, or automatically deleted. Keep its
parent private, outside the repository, and run
`python3 report_export.py verify <bundle>` again before use or transfer.

## Fixed synthetic evidence and browser-capture boundary

Public offline-report evidence is generated only by `report_evidence.py`. It
creates a fixed synthetic SQLite database in a private temporary directory,
proves that unique private-field canaries are present in that source, runs the
standalone exporter twice, verifies the bundle, proves the source database did
not change, and rejects any serialized canary or host path. It accepts no
database, URL, image, timestamp, profile, plate identifier, camera, or output
argument from an operator. Never substitute a real application database into
this public evidence path.

The tracked PNG is a real page-only headless-Chromium rendering of that exact
synthetic bundle. Visible pixels can disclose data even when PNG metadata is
absent, so every changed image requires human visual inspection. The validator
accepts only bounded 1440×2200, 8-bit RGB/RGBA, non-interlaced PNG data with
`IHDR`, contiguous `IDAT`, and `IEND` chunks, valid CRCs, an exact decoded
stream length, and no ancillary text, time, profile, EXIF, or trailing data.
The receipt binds the reviewed PNG hash and dimensions to the report ID, HTML,
generated SVG, capture script, exact container digest, Chromium version and
binary hash, viewport, locale, timezone, and device scale factor.

`tools/capture_offline_report.sh` first verifies the exact managed bundle, then
uses the already-cached container by full digest with `--pull=never`, no
network, a numeric non-root user, a read-only container root, all capabilities
dropped, `no-new-privileges`, and CPU, memory, process, descriptor, and timeout
limits. It mounts only the verified bundle read-only and one fresh output
directory; it never mounts the repository root, home directory, Docker socket,
or a runtime database. Chromium runs with `--no-sandbox` because its user-namespace
sandbox is unavailable on this host. The outer container, Docker daemon, host
kernel/CPU, and local image cache remain trust boundaries; this is not a
hardened-browser-sandbox claim.

`python3 report_evidence.py --check` regenerates the fixed export in private
repository-local temporary storage and byte-compares the tracked artifacts. It
does not change tracked artifacts or launch Docker or Chromium, but it is not a
globally read-only operation and cannot prove that another machine would
produce identical pixels. Recapture uses the exact documented browser and font
image, but rendering can remain host-sensitive. A new screenshot hash must be
manually inspected and deliberately bound; never auto-bless drift. Temporary
fixture, browser profile, cache, and raw capture cleanup is best effort after
process failure, with no secure-memory or secure-erasure claim. Residuals are
synthetic-only, covered by narrow ignore rules, and should still be removed
before committing.

Content addressing and screenshot binding prove internal byte consistency, not
authorship, the identity or truth of a source database, recognition accuracy,
anonymity, authorization, performance, GUI behavior, camera operation, native
DTK behavior, or production readiness. The tracked synthetic exception does
not permit committing an operator-created report.

No legacy artifact migration is included. Older folders or files whose names
came directly from recognition text are not renamed, moved, deleted, or
automatically trusted. Handle them manually only after checking their privacy
and provenance.

## Native dependency boundary

`DTKLPR5.py` and `DTKVID.py` are DTK Software wrapper files. The corresponding
native libraries and licenses are external to this repository. No native DTK
binaries, vendor license keys, or activation material should be committed.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Reporting a vulnerability

Prefer GitHub's private vulnerability-reporting channel for this repository if
it is enabled. Otherwise, contact the repository owner privately before
publishing details. Include affected files, a minimal reproduction using
synthetic data, impact, and suggested remediation. Do not attach real plate
images, camera URLs, credentials, databases, native binaries, license material,
or other personal data.

Public issues are appropriate only after sensitive details and reproduction
artifacts have been removed.
