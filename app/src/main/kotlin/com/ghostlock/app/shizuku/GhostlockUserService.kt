package com.ghostlock.app.shizuku

import android.content.Context
import android.os.Build
import android.os.Process
import androidx.annotation.Keep
import com.ghostlock.app.data.NativeProfileDocument
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

@Keep
class GhostlockUserService(private val context: Context) : IGhostlockUserService.Stub() {
    private val running = AtomicBoolean(false)

    private companion object {
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"
        const val Opd2515WorkDir = "/data/local/tmp/ghostlock-app"
        const val Opd2515BootMarkerName = ".opd2515-boot-id"
        const val Opd2515Model = "OPD2515"
        const val Opd2515Release =
            "6.12.58-android16-6-g7704a1ae279b-ab15213644-4k"
        const val Opd2515PreloaderHash91424 =
            "01C7FE7FEAF5DB79AA239CF76CA7C0DDB909BE9747FCCFAF794A9420D7A4441C"
        const val Opd2515PreloaderHash91720 =
            "CCB15ABD51BB1B1122FF8E916CBE9DB89D3DC6BB162E8111335ED7B02B8FD4EE"
        const val Opd2515PreloaderTimeoutMs = 30_000L
    }

    override fun runExploit(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                require(profileBlob.size >= 16) { "profile blob is too short" }
                // PROFILE-SUGGEST-01: recommend_shizuku is a suggestion; the
                // blob's meta section carries it, and the app already chose the
                // Shizuku path, so it is logged, never a gate.
                if (NativeProfileDocument.fromBinary(profileBlob)?.recommendShizuku != 1u) {
                    callback.onLog("<s> kernel does not require Shizuku; running on user request")
                }

                val binary = File(context.applicationInfo.nativeLibraryDir, "libghostlock.so")
                require(binary.isFile) { "missing GhostLock binary: ${binary.absolutePath}" }

                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("<s> Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("<s> kernel: $release")
                val nativeLog = File(workDir, ".ghostlock_native.log")
                // U01-S14: per-run KernelSU log so a previous run's markers can
                // never satisfy the handoff probe; the native process receives
                // the resolved path via GHOSTLOCK_KSU_LOG.
                val ksuLog = File(workDir, "ghostlock-ksu-${System.currentTimeMillis()}.log")
                // v2: safe_mode lives in the meta section; there is no fixed
                // slot offset, so the blob is rescanned and rewritten.
                val effectiveBlob = if (safeMode) {
                    NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                } else {
                    profileBlob
                }
                val argv = mutableListOf(
                    binary.absolutePath,
                    "--ghostlock-app-call",
                    "--enable-status-record",
                )
                if (forceAttack) {
                    argv += "--force-attack"
                }
                if (!debugDir.isNullOrEmpty()) {
                    argv += listOf("--dump-kernel-log", debugDir)
                }
                callback.onLog("<b> starting native: ${binary.absolutePath}")
                ProcessBuilder(argv)
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                    }
                    .start()
                    .let { process ->
                        val stdinOut = process.outputStream
                        /* Length-prefixed GLK1; stdin stays open for the ACK. */
                        runCatching {
                            val length = effectiveBlob.size
                            stdinOut.write(
                                byteArrayOf(
                                    (length ushr 24).toByte(),
                                    (length ushr 16).toByte(),
                                    (length ushr 8).toByte(),
                                    length.toByte(),
                                ),
                            )
                            stdinOut.write(effectiveBlob)
                            stdinOut.flush()
                        }
                        // The native process writes its log to a file and this
                        // tailer forwards lines asynchronously. Reading a pipe
                        // here applied backpressure inside the PI race window
                        // (every line also costs a binder round trip), which
                        // stalled the route and ended in a kernel panic.
                        val tailer = Thread({
                            relayLog(nativeLog, callback, statusCallback, stdinOut)
                        }, "ghostlock-shizuku-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        val exitCode = process.waitFor()
                        callback.onLog("<b> native exited code=$exitCode")
                        Thread.sleep(200)
                        tailer.interrupt()
                        tailer.join(1000)
                        exitCode
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-runner").start()
    }

    /**
     * Runs only the exact OPD2515 preloader from the shell UserService.
     *
     * The app-UID direct route is intentionally kept out of this method: the
     * device's app process is seccomp-filtered, while the historical preloader
     * evidence was collected from a shell UID with Seccomp=0. This method does
     * not start libghostlock.so or consume a GLK profile.
     */
    override fun runOpd2515Preloader(
        debugDir: String?,
        callback: IGhostlockCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "OPD2515 preloader uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "OPD2515 preloader UserService is still seccomp-filtered"
                }
                require(Build.MODEL.trim() == Opd2515Model) {
                    "OPD2515 preloader model gate failed: ${Build.MODEL}"
                }
                val kernelRelease = System.getProperty("os.version", "").trim()
                require(kernelRelease == Opd2515Release) {
                    "OPD2515 preloader kernel gate failed: $kernelRelease"
                }
                val selinuxContext = File("/proc/self/attr/current").readText().trim()
                require(selinuxContext == "u:r:shell:s0") {
                    "OPD2515 preloader SELinux gate failed: $selinuxContext"
                }

                val source = File(
                    context.applicationInfo.nativeLibraryDir,
                    "libopd2515_preload.so",
                )
                require(source.isFile) { "missing OPD2515 preloader: ${source.absolutePath}" }
                val sourceHash = sha256(source).uppercase()
                require(isKnownOpd2515PreloaderHash(sourceHash)) {
                    "unrecognized OPD2515 preloader SHA-256: $sourceHash"
                }
                val workDir = File(Opd2515WorkDir).apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                    // /data/local/tmp is shared and world-writable. Keep this
                    // staging directory private to the shell owner so another
                    // app cannot replace the payload between hash and exec.
                    require(setReadable(false, false) && setReadable(true, true)) {
                        "cannot make $absolutePath owner-readable"
                    }
                    require(setWritable(true, true)) { "cannot make $absolutePath writable" }
                    require(setExecutable(false, false) && setExecutable(true, true)) {
                        "cannot make $absolutePath owner-searchable"
                    }
                }
                val bootId = File("/proc/sys/kernel/random/boot_id").readText().trim()
                require(bootId.isNotEmpty()) { "kernel boot_id is unavailable; refusing preloader" }
                val bootReason = readCommandOutput("/system/bin/getprop", "ro.boot.bootreason")
                callback.onLog(
                    "<s> OPD2515 preflight: bootId=$bootId " +
                        "bootreason=${bootReason.ifEmpty { "unknown" }}",
                )
                require(!isUnsafeBootReason(bootReason)) {
                    "unsafe bootreason=$bootReason; reboot cleanly before retrying OPD2515"
                }

                val bootMarker = File(workDir, Opd2515BootMarkerName)
                val previousBootId = if (bootMarker.isFile) {
                    bootMarker.readText().trim()
                } else {
                    ""
                }
                require(previousBootId != bootId) {
                    "OPD2515 preloader already attempted in this boot; reboot before retrying"
                }

                val existingSu = File("/data/local/tmp/su")
                if (existingSu.isFile) {
                    val probe = runRootCommand(existingSu, "id")
                    val activeRoot = probe.code == 0 &&
                        Regex("(^|\\s)uid=0(?:\\(|\\s|$)").containsMatchIn(probe.output)
                    if (activeRoot) {
                        callback.onLog(
                            "<b> OPD2515 preflight: temporary root is already active; " +
                                "refusing a second exploit attempt",
                        )
                        return@runCatching 0
                    }
                    callback.onLog(
                        "<s> OPD2515 preflight: stale su exists but is not usable " +
                            "(exit=${probe.code})",
                    )
                }

                // Write the marker before starting the native process. A panic
                // or force-stop must not turn a second tap into a same-boot
                // retry of the high-risk standalone payload.
                bootMarker.writeText("$bootId\n")
                callback.onLog(
                    "<s> OPD2515 preflight: attempt marker written to ${bootMarker.absolutePath}",
                )
                // Use a boot-specific name so an immutable payload from an
                // earlier boot is never overwritten in-place.
                val staged = File(workDir, "libopd2515_preload-$bootId.so")
                source.copyTo(staged, overwrite = true)
                require(staged.setReadable(false, false) && staged.setReadable(true, true)) {
                    "cannot make staged preloader owner-readable"
                }
                require(staged.setWritable(false, false)) { "cannot make staged preloader immutable" }
                require(staged.setExecutable(false, false) && staged.setExecutable(true, true)) {
                    "cannot make staged preloader owner-executable"
                }
                require(sha256(staged).uppercase() == sourceHash) {
                    "staged OPD2515 preloader hash changed during copy"
                }
                val nativeLog = File(workDir, ".ghostlock-opd2515-preloader.log")
                callback.onLog(
                    "<s> OPD2515 preloader ready: uid=${Process.myUid()} Seccomp=0 " +
                        "selinux=$selinuxContext preloader=${staged.absolutePath} " +
                        "preloaderSha256=$sourceHash " +
                        "debugDir=${debugDir ?: "none"}",
                )

                ProcessBuilder("/system/bin/id")
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        // This is the historical, standalone preloader.  Its
                        // anti-root stop is intentionally compiled into the
                        // same library because splitting it into a second
                        // LD_PRELOAD changed the timing/layout and caused a
                        // kernel UBSAN reboot on this exact device.
                        environment()["LD_PRELOAD"] = staged.absolutePath
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_CLIENT_UID"] = Process.myUid().toString()
                    }
                    .start()
                    .let { process ->
                        val tailer = Thread({
                            relayLogSimple(nativeLog, callback)
                        }, "ghostlock-opd2515-preloader-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        var code = if (process.waitFor(Opd2515PreloaderTimeoutMs, TimeUnit.MILLISECONDS)) {
                            process.exitValue()
                        } else {
                            callback.onLog(
                                "<s> OPD2515 preloader timed out after " +
                                    "${Opd2515PreloaderTimeoutMs / 1000}s; terminating it",
                            )
                            process.destroyForcibly()
                            process.waitFor(1, TimeUnit.SECONDS)
                            124
                        }
                        callback.onLog("<b> OPD2515 preloader exited code=$code")
                        tailer.interrupt()
                        tailer.join(1000)
                        if (code == 0) {
                            val postflight = runRootPostflight(callback)
                            if (!postflight) code = 1
                        }
                        code
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-opd2515-preloader").start()
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    private fun readCommandOutput(vararg command: String): String {
        val process = ProcessBuilder(*command)
            .redirectErrorStream(true)
            .start()
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return ""
        }
        return process.inputStream.bufferedReader().use { it.readText().trim() }
    }

    private fun isUnsafeBootReason(reason: String): Boolean =
        reason.contains("kernel_panic", ignoreCase = true) ||
            reason.contains("malicious_app_try_to_root_devices", ignoreCase = true)

    private fun isKnownOpd2515PreloaderHash(hash: String): Boolean =
        hash == Opd2515PreloaderHash91424 || hash == Opd2515PreloaderHash91720

    /**
     * Complete the volatile handoff after the preloader process exits.  The
     * command is intentionally idempotent: it only sends SIGSTOP to the three
     * known OPPO anti-root process names and then probes the temporary su
     * daemon.  It never writes a partition or a persistent property.
     */
    private fun runRootPostflight(callback: IGhostlockCallback): Boolean {
        val su = File("/data/local/tmp/su")
        if (!su.isFile) {
            callback.onLog("<s> root postflight: temporary su is missing")
            return false
        }
        val stopCommand =
            "for name in exsystemservice com.oplus.exsystemservice oplus_kevent; " +
                "do for pid in \$(pidof \$name 2>/dev/null); do kill -STOP \$pid; " +
                "done; done"
        val stop = runRootCommand(su, stopCommand)
        if (stop.output.isNotBlank()) {
            callback.onLog("<s> root postflight output: ${stop.output.trim()}")
        }
        callback.onLog("<s> root postflight anti-root scan exit=${stop.code}")
        if (stop.code != 0) return false

        val probe = runRootCommand(su, "id")
        callback.onLog(
            "<s> root handoff probe exit=${probe.code} output=${probe.output.trim()}",
        )
        return probe.code == 0 && Regex("(^|\\s)uid=0(?:\\(|\\s|$)").containsMatchIn(probe.output)
    }

    private data class RootCommandResult(val code: Int, val output: String)

    private fun runRootCommand(su: File, command: String): RootCommandResult {
        val process = ProcessBuilder(su.absolutePath, "-c", command)
            .redirectErrorStream(true)
            .start()
        val finished = process.waitFor(5, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return RootCommandResult(124, "timeout")
        }
        return RootCommandResult(
            process.exitValue(),
            process.inputStream.bufferedReader().use { it.readText() },
        )
    }

    private fun relayLogSimple(logFile: File, callback: IGhostlockCallback) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) runCatching { callback.onLog(line) }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    /** Forward complete native log lines without ever blocking the native
     * process; the file is the transport, binder is only the display path. */
    /** Forwards status events to the app (persist) and ACKs the native process;
     *  returns true when the line was a status event. */
    private fun handleStatusLine(
        line: String,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            runCatching { statusCallback.onStatus("", "disabled") }
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size >= 2) {
            runCatching { statusCallback.onStatus(parts[0], parts[1]) }
            runCatching {
                stdinOut.write(StatusAck.toByteArray(Charsets.UTF_8))
                stdinOut.flush()
            }
        }
        return true
    }

    private fun relayLog(
        logFile: File,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) {
                                    if (!handleStatusLine(line, statusCallback, stdinOut)) {
                                        runCatching { callback.onLog(line) }
                                    }
                                }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    override fun destroy() {
        if (!running.get()) kotlin.system.exitProcess(0)
    }
}
