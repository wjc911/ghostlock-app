# OPD2515 无 ADB 临时 root 候选审计

## 当前结论

OPD2515 的精确基线是 Android 16、内核
`6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`。目前有两条普通 App
入口值得在平板上做一次性冷启动验证，但没有哪一条可以在没有平板实测日志时称为
“已验证支持 OPD2515”。

### A：CVE-2026-43499 / X9U App-UID 入口

`koaaN/x9u-preload-builder` 在同一精确 kernel release 上公开了普通 App 启动
`/system/bin/sh`、通过 `LD_PRELOAD` 获取 uid 0 的实现；其 X9 Ultra release
记录了 uid/gid 0 和 SELinux `1->0`。本 fork 已把公开 preloader、按 OPD2515
boot/xbl 重建的候选 preloader、每 boot 一次门禁和 app-private broker 放进
实验 APK。

这条证据不能直接外推到 OPD2515：历史 OPD2515 实验中，UID 2000、`Seccomp=0` 的
Shizuku UserService 路线曾成功，而普通 `untrusted_app` 直接启动旧 preloader
曾出现 UBSAN/panic。实验 APK 因此保持 exact model/kernel/hash gate，且未完成冷启动
成功、30 秒存活和重启后清理前，不把它标为稳定支持。

### B：DirtyFrag / CVE-2026-43284

`mitschud/DirtyFrag` v1.11 是独立的 Android APK：Java 侧由普通应用调用
`IpSecManager`，native engine 利用 ESP page-cache 原语并加载 `android16-6.12`
模块；它的公开使用说明明确不要求 ADB 或 Shizuku。当前 fork 的 LKM 源码还包含
OPPO/OnePlus 安全模块名（`oplus_secure_harden`、
`oplus_security_keventupload`、`oplus_security_guard`）的处理。

这条路线比 A 更像真正的“无需 ADB 一键 App”，但仍有三个设备变量必须在 OPD2515
上确认：

1. 6.12.58 是否被 OPPO 单独回移了 DirtyFrag 修复或关闭了所需的 XFRM/USER_NS；
2. `android16-6.12` LKM 的 KMI、模块签名和 OPPO `vendor_modprobe` 是否匹配；
3. 平板的 `/vendor/lib64` 是否有可用的 carrier library，且 anti-root 不会在模块
   handoff 前重启设备。

公开 DirtyFrag APK 的 SHA-256 为：

```text
E09012803EFB74B93413B02E682E44BFD7B9C7931510DB2BBDEE71A747995677
```

它需要一个提供 `libksud.so` 的 KernelSU 管理器；这不是 ADB 权限，但目前仍是第二个
安装前提。

## 平板出现后的一次性验收

每次开机只尝试一条路线，失败后不在同一 boot 重试：

1. 记录 `ro.boot.bootreason`、model、kernel release 和安全补丁；拒绝
   `kernel_panic` 或 `malicious_app_try_to_root_devices` 的 boot。
2. 安装候选 APK；保持屏幕唤醒；运行一次。
3. 成功必须同时看到 uid 0、临时 `su`/broker 可用、设备至少稳定 30 秒，且没有
   anti-root 重启或 UBSAN。
4. 重启后确认 root、daemon、socket 和 per-boot marker 都消失，系统没有写入
   boot/system 分区。

在这些门禁完成前，当前状态是“已找到公开候选和可审计构建”，不是“OPD2515 已验证
一键 root”。

## 公开资料

- [koaaN/x9u-preload-builder](https://github.com/koaaN/x9u-preload-builder)
- [koaaN/x9u-gbl-chainload-app](https://github.com/koaaN/x9u-gbl-chainload-app)
- [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag)
- [OPD2515 exact-kernel baseline](https://github.com/yu1101610062/opd2515-systemd-kernel)
