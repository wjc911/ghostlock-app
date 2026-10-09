# OPD2515 preloader device gate

This record is for the exact target `OPD2515` /
`6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`. It is intentionally kept
separate from the general profile documentation so a panic or reboot cannot be
mistaken for a supported route.

## Required evidence for a PASS

1. APK package and the arm64 standalone preloader are identified by SHA-256.
2. Shizuku UserService reports `uid=2000` and `Seccomp=0` before launch.
3. The process is started with `LD_PRELOAD=preloader`; the exact target
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

## 2026-10-09 — Batch G historical standalone rebuild

The historical device success was reproduced on the host from the `ccd3b62`
preloader sources with Android NDK `27.0.12077973` / Clang 18.0.1. The result
is byte-identical to the device's `preload-app.so` (91720 bytes,
`CCB15ABD51BB1B1122FF8E916CBE9DB89D3DC6BB162E8111335ED7B02B8FD4EE`). The
candidate APK must package that source-built library and load it alone; the
newer Clang build and split `guard:preloader` route are excluded after the
UBSAN reboot. This is an offline build-evidence record, not yet a current-device
PASS: the cold-start gate still requires uid 0, 30-second stability, and the
post-reboot no-root checks above.

## 2026-10-09 — Batch G current-device PASS

The fork APK built from the historical standalone route was installed and run
once on the exact device after a clean reboot. The run used the Shizuku
UserService; no direct app-UID route and no split guard library were used.

- APK: `GhostLock-release-legacy-r27.apk`
- APK SHA-256: `C03CE83899A78A4747DC9D379ECE5C0C368591E84EA4FF488B95C182A3581AD2`
- Packaged standalone preloader: 91424 bytes
- Preloader SHA-256: `01C7FE7FEAF5DB79AA239CF76CA7C0DDB909BE9747FCCFAF794A9420D7A4441C`
- Shizuku preflight: UID 2000, `Seccomp: 0`, `u:r:shell:s0`
- Native evidence: `slide-kaslr-ok`, `direct credential result uid=0`,
  `embedded su daemon ready`, `direct-root-summary root=1`
- Root handoff: `/data/local/tmp/su -c id` returned `uid=0(root)`
- Anti-root guard: `oplus_kevent` and `com.oplus.exsystemservice` were in
  `STAT=T` (temporarily stopped)
- Stability: the device remained online with the su socket and uid 0 for more
  than 40 seconds
- Reboot gate: `ro.boot.bootreason=reboot,shell`, `sys.boot_completed=1`,
  shell returned UID 2000, the su socket was absent, `/data/local/tmp/su -c
  id` returned `Permission denied`, and both anti-root processes were running
  again

Result: **PASS — one-click GhostLock handoff after Shizuku is running; root is
volatile and disappears on reboot.** Starting the Shizuku server still requires
the ADB shell/USB-debugging step after each reboot because a normal application
cannot create a UID-2000 shell process by itself on a locked bootloader.

## 2026-10-09 — Batch H repeat pressure attempt

Status: **FAIL — kernel UBSAN reboot before root handoff**. The same historical
standalone APK and the same Shizuku shell-UID entry were run again as a pressure
test. The native log reached `slide-kaslr-ok` and `direct_root_enter`, then the
device disappeared and rebooted. After reconnect, the bootreason was
`kernel_panic,ubsan:_array_index_out_of_bnulls:_fatal_exception`, shell remained
UID 2000, and `/data/local/tmp/su -c id` returned `Permission denied`.

This is a second failure signal for the route, not evidence of an OPPO anti-root
reboot: the anti-root reboot string was absent and the reboot reason identified
the kernel UBSAN path. The one earlier Batch G success therefore remains a
single-run observation and does not establish stability.

The APK hardening batch adds four fail-closed controls before the native launch:

1. Reject a model/kernel/SELinux context outside the exact validated target and
   reject any preloader SHA other than `01C7FE7F...7A4441C` or the historical
   standalone `CCB15ABD...B8FD4EE`.
2. Reject `kernel_panic` and `malicious_app_try_to_root_devices` boot reasons.
3. Write `/data/local/tmp/ghostlock-app/.opd2515-boot-id` before starting the
   preloader, and refuse a second attempt with the same kernel boot ID.
4. Probe an existing `/data/local/tmp/su`; report an already-active temporary
   root without launching another exploit, and label an unusable file as stale.

The Shizuku runner also uses one connection attempt for this preloader instead
of its normal three-attempt reconnect loop. These controls reduce repeat-trigger
risk; they do not change the native payload or make the exploit stable.

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
