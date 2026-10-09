package com.ghostlock.app.shizuku

import android.content.Context
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

                val source = File(
                    context.applicationInfo.nativeLibraryDir,
                    "libopd2515_preload.so",
                )
                require(source.isFile) { "missing OPD2515 preloader: ${source.absolutePath}" }
                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                val staged = File(workDir, "libopd2515_preload.so")
                source.copyTo(staged, overwrite = true)
                staged.setReadable(true, false)
                staged.setExecutable(true, false)
                val nativeLog = File(workDir, ".ghostlock-opd2515-preloader.log")
                callback.onLog(
                    "<s> OPD2515 preloader ready: uid=${Process.myUid()} Seccomp=0 " +
                        "preloader=${staged.absolutePath} " +
                        "preloaderSha256=${sha256(staged)} " +
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
                        var code = process.waitFor()
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
