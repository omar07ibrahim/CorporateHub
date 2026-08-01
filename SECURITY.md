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
not currently implement encryption, authentication, authorization, redaction,
retention enforcement, or a verified deletion workflow.

Keep all generated data outside version control and restrict filesystem access
at the operating-system boundary. Do not include credentials in RTSP URLs used
for development evidence. Review images and reports for personal data before
sharing them.

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
still race later operations. Other legacy read, copy, export, database, and
logging paths have not received equivalent review. In particular, the HTML
report generator and image-copy logic are unchanged and have not been
runtime-tested.

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
