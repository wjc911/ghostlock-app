# OPD2515 preloader device gate

This record is for the exact target `OPD2515` /
`6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`. It is intentionally kept
separate from the general profile documentation so a panic or reboot cannot be
mistaken for a supported route.

## Required evidence for a PASS

1. APK package and both arm64 JNI libraries are identified by SHA-256.
2. Shizuku UserService reports `uid=2000` and `Seccomp=0` before launch.
3. The process is started with `LD_PRELOAD=guard:preloader`; the exact target
   release and model gate is visible in the app log.
4. The app reports `su -c id` as uid 0 and the anti-root postflight exits 0.
5. The device stays up for at least 30 seconds after the run.
6. After a user initiated reboot, shell is uid 2000, the temporary socket and
   daemon are unavailable, and no boot or system partition hash changed.

## 2026-10-09 — Batch F integration

- Status: **NOT RUN**.
- Host source build: guard compiled as AArch64 ELF; preloader source compiled
  with the local r27 toolchain for syntax/ELF checks. The release APK still
  requires CI's ONDK r30.1 build before device installation.
- Device: current session has a historical temporary root, so it must not be
  used as the cold-start result for this batch.
- Failure policy: no shift variants, no repeated direct app-UID route, and no
  automatic retry after a kernel panic or reboot.

## Run record template

```text
APK:
APK SHA256:
preloader SHA256:
guard SHA256:
model:
release:
Shizuku UID/Seccomp:
root handoff output:
anti-root process state:
30s stability:
post-reboot shell uid:
post-reboot su probe:
bootreason:
partition/hash observations:
result: PASS / FAIL
```
