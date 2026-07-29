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
