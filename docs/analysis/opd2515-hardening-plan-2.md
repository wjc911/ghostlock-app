# OPD2515 staging hardening — second pass

## Scope

This batch changes only the Kotlin-side preparation of the existing, exact
OPD2515 preloader. It does not change the native payload, its command line,
its environment contract, or the direct app-UID route. The goal is to make a
previously-created `/data/local/tmp/ghostlock-app` tree unable to influence a
new boot's staging run through leftover permissions or symbolic links.

## Design

1. Clear all non-owner directory permissions before restoring owner access.
2. Reject a symbolic-link boot marker instead of reading or overwriting its
   target.
3. Remove a pre-existing staged payload path after the directory is private;
   this makes a stale link harmless before the copy.
4. Use a boot-specific native log name and reject a symbolic-link log path.

The native preloader, its one-shot boot marker, timeout, hash allow-list,
model/kernel/SELinux gates, and postflight probe remain unchanged.

## Verification

- `:app:assembleRelease` through the fork's GitHub Actions workflow.
- Confirm the packaged preloader hash and APK SHA-256.
- Install the signed artifact through the device's package installer and open
  GhostLock; do not execute the OPD2515 payload after the recorded UBSAN
  reboot.
- Record the no-ADB reboot boundary separately: Android/ColorOS may run
  Shizuku's boot receiver before Wi-Fi is ready, so this batch does not claim
  automatic post-reboot shell access.
