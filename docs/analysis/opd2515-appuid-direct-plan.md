# OPD2515 App-UID temporary-root route plan（2026-10-10）

## 现状与基线

基线分支为 `opd2515-robustness`，其 exact OPD2515 preloader gate 保持关闭：
一次历史运行曾达到 `uid=0`，随后重复运行触发 kernel UBSAN 重启，因此该分支不把
Shizuku/shell-UID 路径标记为稳定。平板的 exact kernel 为
`6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`。

公开的 [X9U preload builder](https://github.com/koaaN/x9u-preload-builder) 已在同一
kernel 字符串、同一 OPPO 系列上验证普通 App UID 通过 `LD_PRELOAD` 获得临时 root。
平板的 `boot-current.img` 与 `xbl_config-current.img` 已本地重新生成 target header；
生成的关键偏移与平板已有 target header 一致，`PSELECT_WAITER_WORD_SHIFT=14`。

## 目标与约束

目标是提供一个单独、明确标识的实验 APK：不依赖 ADB 或 Shizuku，由普通 App UID 启动
精确的 OPD2515 preloader，并把临时 root 交给现有 `/data/local/tmp/su` broker。

约束：

- 只接受 `Build.MODEL=OPD2515` 与 exact `uname -r`；
- 只接受从平板匹配 boot/xbl 生成、并经 SHA-256 固定的 preloader；
- 不写 boot/vendor/system 分区、不改 bootloader 状态；
- 每个 boot 只允许一次尝试；检测 `kernel_panic` 或 anti-root 恶意启动原因后拒绝；
- 普通 GhostLock APK 与 `opd2515-robustness` 分支继续 fail-closed；实验行为由
  `-Popd2515DirectExperimental=true` 构建属性显式开启；
- 未完成真机冷启动、30 秒存活、root handoff、重启后清理四项门禁前，不称为
  `supported` 或“稳定”。

## 改动清单

| 文件 | 改动 | 理由 |
| --- | --- | --- |
| `app/build.gradle.kts` | 增加 `OPD2515_DIRECT_EXPERIMENTAL` BuildConfig 字段 | 防止普通构建误启用高风险入口 |
| `app/src/main/kotlin/com/ghostlock/app/data/AndroidGhostlockRepository.kt` | 增加 exact target gate、App-UID `LD_PRELOAD` 启动、每 boot marker、日志与 root postflight | 复用已验证的 X9U App-UID 入口，保持现有 UI/日志契约 |
| `.github/workflows/build.yml` | 实验分支构建时传入 opt-in property，并核验 preloader hash | 生成可审计的实验 APK |
| `docs/analysis/device-gates/OPD2515-appuid-direct-plan.md` | 记录设计、边界与验证矩阵 | 使未验证状态可追溯 |

## 数据流/控制流差异

```mermaid
flowchart TD
    A[GhostLock App UID] --> B{exact model + kernel + hash}
    B -- fail --> R[拒绝并记录原因]
    B -- pass --> C{本 boot marker / bootreason / 已有 su}
    C -- unsafe or repeated --> R
    C -- clean --> D[ProcessBuilder /system/bin/id\nLD_PRELOAD=libopd2515_preload.so]
    D --> E[preloader: CVE-2026-43499\ncredential + SELinux handoff]
    E --> F[write /data/local/tmp/su\nstart root broker]
    F --> G[App UID su -c id + stop known anti-root tasks]
    G -- uid=0 --> H[temporary root ready]
    G -- fail --> R
```

原有安全分支仍走：普通 profile → `libghostlock.so`，或 exact OPD2515 → Shizuku
preloader（当前 gate 关闭）。实验构建只对 exact OPD2515 把“运行入口”切换为上图；
其余 kernel 的行为不变。

## 兼容性与回滚

卸载实验 APK、重启设备或删除 app-private marker 即可撤销 App 层改动；preloader 的
root 与 `su` daemon 本身是易失状态，重启后消失。源码回滚只需切回
`opd2515-robustness`；实验分支不向原始仓库推送。

## 验证矩阵

| 批次 | 验证 | 通过条件 |
| --- | --- | --- |
| A | Kotlin/Gradle unit tests | 编译通过，普通构建 `BuildConfig=false` |
| B | APK 静态检查 | 仅 arm64 包含 preloader；hash 为 `CCB15...F4EE`；实验 APK 字段为 true |
| C | 平板干净启动 | bootreason 无 panic，首次运行只执行一次，日志含 target/hash |
| D | 临时 root | 日志含 `uid=0`、`su daemon ready`、postflight `uid=0`，设备 30 秒不重启 |
| E | 重启复测 | root/marker 旧状态不被误用；新 boot 可在用户主动点击后再次尝试 |

目前只完成 A 的代码准备和 B 的本地 target/preloader 重建；C–E 必须在平板在线后
执行，不能从构建结果推断成功。

## 明确保留

- 不改 `src/` 的通用 native route、profile wire 或 kernelsnitch；
- 不改变原有 `ShizukuExploitRunner` 的 shell-UID 代码；
- 不使用 X9U 的预编译 payload；每个设备仍必须从自己的 boot/xbl 重新生成；
- 不执行分区写入、GBL chainload 或 bootloader 解锁。

## 进度

- [x] 从平板 boot/xbl 重新生成 target header
- [x] 用 NDK r27 重建 exact OPD preloader，hash 固定
- [x] 增加 opt-in App-UID Android 入口与 per-boot fail-closed guard
- [ ] 本地/CI 编译实验 APK
- [ ] 平板冷启动真机门禁
- [ ] 重启后再次激活门禁
