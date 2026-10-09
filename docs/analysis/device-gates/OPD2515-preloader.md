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

## 2026-10-09 — Batch F integration and cold-start gate

- Status: **FAIL**. The route was integrated, built in CI, installed, and
  launched through Shizuku's shell-UID UserService. It did not produce root.
- APK SHA-256: `88ee69de22b80e413dc7bf83076da36dbf96dc749b4f270904386d9b8ffb7f9a`.
- Packaged arm64 libraries:
  - `libopd2515_preload.so`:
    `5b3d1ff5dc4c73643f5f600ce22960de481164c77173ac83f66c9c820b600778`
  - `libopd2515_root_guard.so`:
    `4987a505d2a9bacae9d6897863c8eda7b7c996b689338126c5b0cb7e7eec8664`
- Device: `OPD2515`, release
  `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`.
- Shizuku preflight: `uid=2000`, `Seccomp=0`, permission granted; the app log
  selected the shell-UID preloader and recorded `LD_PRELOAD=guard:preloader`.
- Native log at `2026-10-09 13:56:25` reached `slide requeue ret=-1 errno=35`
  and stopped there. The device then disappeared from ADB and rebooted.
- Root handoff: **not reached**. After reconnect, shell remained uid 2000 and
  `/data/local/tmp/su -c id` returned `su: connect daemon: Permission denied`.
- Stability: **0/30 seconds**; the device rebooted during the first attempt.
- Post-reboot: `getenforce=Enforcing`, verified boot remained `green`, and the
  anti-root processes were running again. `ro.boot.bootreason` was
  `kernel_panic,ubsan:_array_index_out_of_bounds:_fatal_exception`.
- No partition-writing step was present in this route; partition hash
  preservation was not used as a success criterion because root was never
  established.
- Safety action: the exact OPD2515 profile is now fail-closed in the app until
  a new offline-reviewed preloader passes this gate. No shift variants,
  repeated direct route, or automatic retry is allowed.

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
result: FAIL — kernel UBSAN reboot before root handoff
```
