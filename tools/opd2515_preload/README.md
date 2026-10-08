# OPD2515 temporary-root preloader

This directory contains the reproducible source for the exact
`OPD2515_16.0.10.500(CN01)` / `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`
temporary-root entry used by the fork. It is built from source in CI; no
precompiled exploit payload is checked in.

The target header is intentionally release-specific. It must not be reused for
another OPPO build or kernel. The resulting arm64 shared object is packaged
only for the fork's OPD2515 application path.
