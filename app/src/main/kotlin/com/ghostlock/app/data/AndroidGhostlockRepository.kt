package com.ghostlock.app.data

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import android.system.Os
import androidx.core.content.edit
import androidx.core.net.toUri
import com.ghostlock.app.BuildConfig
import com.ghostlock.app.BuildInfo
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.DebugSettings
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.OffsetCandidate
import com.ghostlock.app.data.ota.OtaPayloadExtractor
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.UserProfileFile
import com.ghostlock.app.domain.repository.GhostlockRepository
import com.ghostlock.app.domain.repository.ProfileConfigController
import com.ghostlock.app.shizuku.ShizukuExploitRunner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Android implementation of the domain repository. All platform I/O lives here. */
class AndroidGhostlockRepository(context: Context) : GhostlockRepository {
    private companion object {
        const val OffsetsFileName = "offsets.conf"
        const val LegacyOffsetsFileName = "offsets.json"
        const val UserProfilesDirectoryName = "user_profiles"
        const val EditSessionPreferences = "ghostlock_edit_session"
        const val ExtractBinaryName = "libextract.so"
        const val Opd2515Release =
            "6.12.58-android16-6-g7704a1ae279b-ab15213644-4k"
        val Opd2515PreloaderHashes = setOf(
            // Windows NDK r27 build used during local reconstruction.
            "CCB15ABD51BB1B1122FF8E916CBE9DB89D3DC6BB162E8111335ED7B02B8FD4EE",
            // Linux NDK r27 build packaged by the fork's GitHub Actions runner.
            "01C7FE7FEAF5DB79AA239CF76CA7C0DDB909BE9747FCCFAF794A9420D7A4441C",
        )
        /* Byte-for-byte copy of koaaN's physically validated X9U App-UID
         * preloader.  The OPD2515 target.h and the X9U target.h are identical
         * for this kernel release; keep this as a separate artifact so the
         * CI-built OPD variant cannot silently replace the validated payload. */
        const val Opd2515X9uPreloaderHash =
            "32AC2F03F56955C41032157AA53F23590C3F6A1595FCCC025AD991322E07F7F6"
        /** Rebuilt from the public X9U source with the OPD2515 target header and NDK r27. */
        const val Opd2515X9uOpdRebuiltPreloaderHash =
            "A4EBA1AE0AB3A9F420DC9B75181F70B49FF725192CF0933F15E36A0861511519"
        const val Opd2515Model = "OPD2515"
        /* The validated X9U App-UID runner allows a long native window.  Keep
         * the OPD port similarly generous: this is a one-shot-per-boot
         * operation, so killing a still-progressing race at 30 seconds is
         * worse than waiting. */
        const val Opd2515PreloaderTimeoutMs = 120_000L
        const val Opd2515DirectReadyName = ".opd2515-direct-root-ready"
        /* This is deliberately a build-time opt-in.  The normal fork remains
         * fail-closed until the exact device route has a fresh cold-boot
         * validation record. */
        val Opd2515DirectExperimental = BuildConfig.OPD2515_DIRECT_EXPERIMENTAL
        /*
         * The exact-device preloader once reached uid=0, but a repeat run on
         * the same OPD2515 reached the kernel UBSAN path and rebooted before
         * handoff.  A single historical success is not a stability gate.
         * Keep this false until a new offline-reviewed payload passes the
         * cold-boot, 30-second, and post-reboot checks documented in
         * docs/analysis/device-gates/OPD2515-preloader.md.
         */
        const val Opd2515PreloaderValidated = false
        const val DefaultDebugLocation = "Download/ghostlock-debug-log"
        const val PrefForceAttackTest = "force_attack_test"
        const val PrefDebugExportEnabled = "debug_export_enabled"
        const val PrefDebugExportLocation = "debug_export_location"
        const val PrefDebugKernelLogEnabled = "debug_kernel_log_enabled"
        const val PrefDebugProfileOverrides = "debug_profile_overrides"

        /* U01-S14: per-run KernelSU log name; the resolved path travels to
         * the native process via GHOSTLOCK_KSU_LOG. */
        fun ksuLogName(runStamp: Long) = "ghostlock-ksu-$runStamp.log"

        /* Every run's stdout/stderr is redirected here (export or not), so the
         * previous run can be inspected on the next start-up. */
        const val NativeLogFileName = ".ghostlock_native.log"

        /* Attack step status persisted by the app. The native process reports
         * each step on stdout and waits for an ACK on stdin; the app owns the
         * file so a kernel panic still leaves the last in_progress step for the
         * next launch to read. HOCON/JSON. */
        const val RunStateFileName = ".ghostlock_run_state.json"
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"
    }

    private val appContext = context.applicationContext
    private val filesDir: File = appContext.filesDir
    private val preferences get() =
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val offsetsFile get() = File(filesDir, OffsetsFileName)
    private val builtinProfiles = BuiltinProfileCatalog(appContext)
    private val assetConfigLoader = AssetConfigLoader(appContext)
    private val userProfileStore = UserProfileStore(
        directory = File(filesDir, UserProfilesDirectoryName),
        assetLoader = assetConfigLoader,
    )
    private val profileController = AndroidProfileConfigController(
        appContext,
        filesDir,
        userProfileStore,
        preferences,
    )
    private val cpuPairs = mutableListOf<CpuPair>()
    private val cpuPairLabels = mutableListOf<String>()
    private var selectedCpuPair = 0
    private var safeModeEnabled = false
    private var forceAttackTest = false
    private var shizukuEnabled = false
    /** True once the user flipped the toggle; only then does it override the
     * profile suggestion (PROFILE-SUGGEST-01). */
    private var shizukuPreferenceSet = false
    private var pendingParsedDocument: PendingParsedDocument? = null
    private val shizukuRunner = ShizukuExploitRunner(appContext)

    init {
        buildCpuPairs()
        restoreCpuPair()
        restoreShizukuPreference()
        restoreForceAttackTest()
        dropLegacyOffsetsCache()
        migrateLegacyOffsetsStore()
    }

    /** The old JSON offsets cache is not compatible and is discarded. */
    private fun dropLegacyOffsetsCache() {
        runCatching { File(filesDir, LegacyOffsetsFileName).delete() }
    }

    /**
     * Old builds kept imported offsets and parameter overrides in one HOCON
     * file. Split it: overrides move to preferences, the remaining entries
     * become verbatim user documents, then the legacy file is dropped.
     */
    private fun migrateLegacyOffsetsStore() {
        if (!offsetsFile.isFile) return
        runCatching {
            val entries = parseEntries(offsetsFile.readText()) ?: return@runCatching
            for (raw in entries) {
                val entry = raw.asValueMap() ?: continue
                val release = (entry["release"] as? String).orEmpty()
                if (release.isEmpty()) continue
                val overrides = valueMapOf()
                (entry.remove("execution") as? Map<*, *>)?.let { overrides["execution"] = it }
                (entry.remove("route") as? Map<*, *>)?.let { overrides["route"] = it }
                (entry.remove("fallback") as? Map<*, *>)?.let { overrides["fallback"] = it }
                if (overrides.isNotEmpty()) mergeLegacyOverrides(release, overrides)
                if (entry.size > 1) {
                    userProfileStore.save("$release.conf", HoconSupport.render(entry))
                }
            }
            offsetsFile.delete()
        }.onFailure {
            android.util.Log.e("GhostLock", "legacy offsets migration failed", it)
        }
    }

    private fun mergeLegacyOverrides(release: String, overrides: ValueMap) {
        val raw = preferences.getString(PrefDebugProfileOverrides, null)
        val all = runCatching { HoconSupport.parseValue(raw ?: "") }
            .getOrNull().asValueMap() ?: valueMapOf()
        deepMergeValues(all.mutableChild(release), overrides)
        preferences.edit { putString(PrefDebugProfileOverrides, HoconSupport.render(all)) }
    }

    override suspend fun snapshot(): KernelSnapshot {
        val release = System.getProperty("os.version", "unknown").orEmpty()
        val exactOpd2515 = isOpd2515Target(release)
        val exactOpd2515Blocked = exactOpd2515 &&
            !Opd2515PreloaderValidated && !Opd2515DirectExperimental
        /* PROFILE-SUGGEST-01: recommend_shizuku is a suggestion. It seeds the
         * toggle until the user makes an explicit choice, which then overrides
         * it in both directions. */
        val recommendShizuku = !exactOpd2515Blocked && !exactOpd2515 &&
            (release in builtinProfiles.recommendShizuku || importedOffsetsRecommendShizuku(release))
        // Do not let a stale preference make a fail-closed exact target look
        // runnable or request a fresh Shizuku grant. The preference itself is
        // retained so a future, separately validated profile can opt in again.
        val shizukuActive = if (exactOpd2515Blocked || exactOpd2515) {
            false
        } else if (shizukuPreferenceSet) {
            shizukuEnabled
        } else {
            recommendShizuku
        }
        return KernelSnapshot(
            deviceName = resolveDeviceName(),
            kernelRelease = release,
            socName = resolveSocName(),
            kernelSupported = isKernelSupported(),
            cpuPairs = cpuPairs.toList(),
            cpuPairLabels = cpuPairLabels.toList(),
            selectedCpuPair = selectedCpuPair,
            safeModeEnabled = safeModeEnabled,
            forceAttackTest = forceAttackTest,
            recommendShizuku = recommendShizuku,
            shizukuEnabled = shizukuActive,
            shizukuStatus = if (shizukuActive) shizukuRunner.status()
            else com.ghostlock.app.domain.model.ShizukuStatus.NOT_REQUIRED,
        )
    }

    override fun selectCpuPair(index: Int) {
        if (index !in cpuPairs.indices) return
        selectedCpuPair = index
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).edit {
                putString("cpu_pair", cpuPairs[index].toString())
            }
    }

    override fun setSafeModeEnabled(enabled: Boolean) {
        safeModeEnabled = enabled
    }

    override fun setForceAttackTest(enabled: Boolean) {
        forceAttackTest = enabled
        preferences.edit { putBoolean(PrefForceAttackTest, enabled) }
    }

    override fun setShizukuEnabled(enabled: Boolean) {
        shizukuEnabled = enabled
        shizukuPreferenceSet = true
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            .edit {
                putBoolean("shizuku_enabled", enabled)
                putBoolean("shizuku_explicit", true)
            }
        if (enabled) shizukuRunner.requestPermission()
    }

    override fun profileController(): ProfileConfigController = profileController

    /* debug-ui: preferences for the hidden debug screen. */
    override suspend fun debugSettings(): DebugSettings = DebugSettings(
        exportEnabled = preferences.getBoolean(PrefDebugExportEnabled, true),
        exportLocation = normalizeDebugLocation(preferences.getString(PrefDebugExportLocation, null)),
        kernelLogEnabled = preferences.getBoolean(PrefDebugKernelLogEnabled, true),
    )

    override fun setDebugExportEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugExportEnabled, enabled) }
    }

    override fun setDebugExportLocation(location: String) {
        preferences.edit { putString(PrefDebugExportLocation, normalizeDebugLocation(location)) }
    }

    override fun setDebugKernelLogEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugKernelLogEnabled, enabled) }
    }

    private fun normalizeDebugLocation(value: String?): String {
        val cleaned = value.orEmpty().trim().trim('/').replace(Regex("/{2,}"), "/")
        val safe = cleaned.takeIf { candidate ->
            candidate.isNotEmpty() && candidate.split('/').none { it == ".." || it == "." }
        }
        return safe ?: DefaultDebugLocation
    }

    /* Profile configuration now lives in AndroidProfileConfigController: the
     * repository only wires it and forwards the native document. */

    override suspend fun importOffsets(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = false)

    override suspend fun confirmImport(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = true)

    private fun mergeImported(documents: Map<String, String>, overwrite: Boolean): OffsetImportResult {
        return try {
            val imported = parseImportDocuments(documents)
                ?: return OffsetImportResult.Failed("not a valid profile document")
            /* Unlike export candidates, imports are never compared against the
             * bundled tables: whatever the user picked lands in the store. */
            val fresh = imported.filter { (it["release"] as? String).orEmpty().isNotEmpty() }
            if (fresh.isEmpty()) return OffsetImportResult.AlreadyPresent

            val releases = freshReleases(fresh)
            val overlaps = releases.filter { userProfileStore.containsRelease(it) }
            if (!overwrite && overlaps.isNotEmpty()) {
                return OffsetImportResult.RequiresOverwrite(overlaps)
            }
            if (overwrite) dropReplacedDocuments(releases)
            for ((name, text) in documents) userProfileStore.save(name, text)
            OffsetImportResult.Imported(releases)
        } catch (error: CancellationException) {
            throw error
        } catch (error: UserProfileStore.MissingIncludes) {
            OffsetImportResult.MissingIncludes(error.files)
        } catch (error: Exception) {
            OffsetImportResult.Failed(error.message ?: "import failed")
        }
    }

    /** Confirmed overwrite: drop old documents fully superseded by [releases]. */
    private fun dropReplacedDocuments(releases: List<String>) {
        val incoming = releases.toSet()
        userProfileStore.list().forEach { stored ->
            if (stored.releases.isNotEmpty() && stored.releases.all { it in incoming }) {
                userProfileStore.delete(stored.name)
            }
        }
    }

    /**
     * Parses every picked document, resolving includes against the picked
     * files first (by full name or base name), then the bundled assets.
     * Anything unresolvable is reported so the user can pick it too; only
     * objects carrying a `release` become entries.
     */
    private fun parseImportDocuments(documents: Map<String, String>): List<ValueMap>? {
        val entries = mutableListOf<ValueMap>()
        documents.forEach { (_, text) ->
            entries += userProfileStore.parseEntries(text, extraDocuments = documents)
        }
        return entries.takeIf { it.isNotEmpty() }
    }

    override suspend fun parseSource(
        input: String,
        xblPath: String?,
        uefiPath: String?,
        vendorBootPath: String?,
        overwrite: Boolean,
        onLog: (String) -> Unit,
    ): ParseResult {
        val parsedFile = File(filesDir, "offsets_parse.tmp")
        var tempBootFile: File? = null
        var tempXblFile: File? = null
        return try {
            if (overwrite) {
                val pending = pendingParsedDocument
                if (pending != null) {
                    pendingParsedDocument = null
                    dropReplacedDocuments(pending.releases)
                    userProfileStore.save(pending.name, pending.text)
                    return ParseResult.Parsed(pending.releases, pending.missing, pending.name)
                }
            }
            val binary = File(appContext.applicationInfo.nativeLibraryDir, ExtractBinaryName)
            if (!binary.isFile) return ParseResult.Failed(1, "missing native binary: ${binary.absolutePath}")

            /* Remote OTA URLs are resolved by the pure-Kotlin extractor so the
             * Android binary ships without the http stack; local files keep
             * going straight to the Rust extractor. */
            val isRemoteUrl = input.startsWith("http://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true)
            val (effectiveInput, effectiveXblPath) = if (isRemoteUrl) {
                val extracted = OtaPayloadExtractor.extractPartitions(
                    url = input,
                    workDir = filesDir,
                    onLog = onLog,
                )
                tempBootFile = extracted.bootFile
                tempXblFile = extracted.xblConfigFile
                Pair(extracted.bootFile.absolutePath, extracted.xblConfigFile?.absolutePath ?: xblPath)
            } else {
                Pair(input, xblPath)
            }

            parsedFile.delete()
            val args = buildList {
                add(effectiveInput)
                if (effectiveXblPath != null) {
                    add("--xbl-config")
                    add(effectiveXblPath)
                }
                if (uefiPath != null) {
                    add("--uefi")
                    add(uefiPath)
                }
                if (vendorBootPath != null) {
                    add("--vendor-boot")
                    add(vendorBootPath)
                }
                /* --format conf: the extractor output is already the flattened
                 * profile (no includes, credential template inlined), so the
                 * stored document needs no legacy conversion. */
                addAll(listOf("--format", "conf", "--out", parsedFile.absolutePath, "--work-dir", filesDir.absolutePath))
            }
            onLog("<k> extract: $effectiveInput")
            val code = runProcess(
                ProcessBuilder(listOf(binary.absolutePath) + args).directory(filesDir).redirectErrorStream(true).apply {
                        environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                        environment()["TMPDIR"] = filesDir.absolutePath
                        environment()["HOME"] = filesDir.absolutePath
                    },
                onLog = onLog,
                timeoutSeconds = 1800,
            )
            onLog("<k> extract exit code=$code")
            if (code != 0 || !parsedFile.isFile) return ParseResult.Failed(code)
            val document = parsedFile.readText()
            val fresh = parseEntries(document) ?: return ParseResult.Failed(code, "invalid extractor output")
            /* Parsed reports are stored as-is, even when they match a bundled
             * profile; loading decides whether they take effect. */
            val filtered = fresh.mapNotNull { it.asValueMap() }
                .filter { (it["release"] as? String).orEmpty().isNotEmpty() }
            if (filtered.isEmpty()) return ParseResult.AlreadyPresent
            val releases = freshReleases(filtered)
            val missing = missingSidecarFields(filtered)
            val overlaps = releases.filter { userProfileStore.containsRelease(it) }
            val name = parsedDocumentName(releases)
            if (!overwrite && overlaps.isNotEmpty()) {
                pendingParsedDocument = PendingParsedDocument(name, document, releases, missing)
                return ParseResult.RequiresOverwrite(overlaps, missing)
            }
            dropReplacedDocuments(releases)
            userProfileStore.save(name, document)
            ParseResult.Parsed(releases, missing, name)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            ParseResult.Failed(1, error.message)
        } finally {
            parsedFile.delete()
            tempBootFile?.delete()
            tempXblFile?.delete()
        }
    }

    override suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int =
        withDebugAttackLog("direct", onLog) { archivedLog, debugDir, writeSidecar ->
            val release = System.getProperty("os.version", "").orEmpty()
            if (isOpd2515Target(release)) {
                if (Opd2515DirectExperimental) {
                    return@withDebugAttackLog runOpd2515DirectPreloader(
                        archivedLog,
                        debugDir,
                        writeSidecar,
                    )
                }
                archivedLog(
                    "<s> error: direct app-UID route is disabled for exact OPD2515; " +
                        "enable Shizuku to run the shell-UID preloader",
                )
                return@withDebugAttackLog 2
            }
            runExploitBinary(pair, "libghostlock.so", archivedLog, debugDir, writeSidecar)
        }

    override suspend fun runExploitWithShizuku(pair: CpuPair, onLog: (String) -> Unit): Int {
        return withDebugAttackLog("shizuku", onLog) { archivedLog, debugDir, writeSidecar ->
            archivedLog("<s> resolving profile")
            val release = System.getProperty("os.version", "").orEmpty()
            if (isOpd2515Target(release)) {
                /* Keep the proven shell-UID route independent from the
                 * ordinary-App experiment.  The experiment is selected by
                 * runExploit() only; a Shizuku invocation must continue to
                 * use UserService (uid=2000, Seccomp=0), because the historic
                 * OPD2515 success and the direct-App path have different
                 * kernel-side timing and postflight requirements. */
                if (!Opd2515PreloaderValidated) {
                    archivedLog(
                        "<s> error: exact OPD2515 preloader is disabled after " +
                            "the kernel-UBSAN reboot; no retry is permitted until " +
                            "the device gate is PASS",
                    )
                    return@withDebugAttackLog 3
                }
                archivedLog("<b> exact OPD2515: selecting shell-UID preloader via Shizuku")
                resetRunState()
                return@withDebugAttackLog shizukuRunner.run(
                    pair = pair,
                    safeMode = safeModeEnabled,
                    forceAttack = forceAttackTest,
                    profileBlob = ByteArray(0),
                    debugDir = debugDir,
                    onLog = archivedLog,
                    opd2515Preloader = true,
                )
            }
            val config = profileController.load(release, pair)
            val profileBlob = profileController.nativeDocument(config)
            archivedLog(
                "<s> profile resolved hasProfile=${config.hasProfile} " +
                    "blob=${profileBlob?.size ?: 0} invalid=${config.invalidPaths.size}",
            )
            when {
                !config.hasProfile || profileBlob == null -> {
                    archivedLog("<s> error: profile is unavailable for $release")
                    1
                }

                config.invalidPaths.isNotEmpty() -> {
                    archivedLog(
                        "<s> error: profile has ${config.invalidPaths.size} invalid field(s): " +
                            config.invalidPaths.take(6).joinToString(),
                    )
                    1
                }

                else -> {
                    /* Mirror the UserService patch so the dumped blob is the
                     * effective one native will actually receive. */
                    val runtimeBlob = if (safeModeEnabled) {
                        NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                    } else {
                        profileBlob
                    }
                    dumpRuntimeProfile(archivedLog, writeSidecar, release, pair, runtimeBlob)
                    archivedLog("<b> starting UserService")
                    resetRunState()
                    shizukuRunner.run(
                        pair = pair,
                        safeMode = safeModeEnabled,
                        forceAttack = forceAttackTest,
                        profileBlob = profileBlob,
                        debugDir = debugDir,
                        onLog = archivedLog,
                        onStatus = { step, status ->
                            if (status == "disabled") clearRunState() else applyRunStatus(step, status)
                        },
                    )
                }
            }
        }
    }

    /* --- attack step status ------------------------------------------------
     * The native process reports each step over stdout and waits for an ACK on
     * stdin. The app persists the status here; a kernel panic leaves the last
     * in_progress step on disk for the next launch to read. */

    private val runStateLock = Any()
    private var runSteps: LinkedHashMap<String, String> = LinkedHashMap()

    private fun persistRunStateLocked() {
        val json = RunStateCodec.encode(runSteps, System.currentTimeMillis())
        runCatching {
            FileOutputStream(File(filesDir, RunStateFileName)).use { out ->
                out.write(json.toByteArray(StandardCharsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
        }
    }

    private fun resetRunState() = synchronized(runStateLock) {
        runSteps = LinkedHashMap<String, String>().apply {
            RunStateCodec.Steps.forEach { put(it, RunStateCodec.NotStarted) }
        }
        persistRunStateLocked()
    }

    private fun applyRunStatus(step: String, status: String) = synchronized(runStateLock) {
        if (!runSteps.containsKey(step)) return@synchronized
        runSteps[step] = status
        persistRunStateLocked()
    }

    private fun clearRunState() = runCatching { File(filesDir, RunStateFileName).delete() }

    /** Handles one stdout line; true when it was a status event, not a log line. */
    private fun handleStatusLine(line: String, process: AtomicReference<Process?>): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            clearRunState()
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size < 2) return true
        applyRunStatus(parts[0], parts[1])
        runCatching {
            process.get()?.outputStream?.apply {
                write(StatusAck.toByteArray(StandardCharsets.UTF_8))
                flush()
            }
        }
        return true
    }

    /**
     * Experimental OPD2515 App-UID entry point.
     *
     * The X9U reference app launches a normal system binary from an ordinary
     * application process with the exact, device-generated preload library in
     * LD_PRELOAD.  This method mirrors that narrow handoff without Shizuku or
     * ADB.  It is compiled into a separately opt-in APK only; the normal fork
     * never reaches it.  All state is volatile except for the private
     * per-boot guard and diagnostic log in the app's own data directory.
     */
    private suspend fun runOpd2515DirectPreloader(
        onLog: (String) -> Unit,
        debugDir: String?,
        writeSidecar: (String, ByteArray) -> Boolean,
    ): Int = withContext(Dispatchers.IO) {
        try {
            require(Build.MODEL.trim() == Opd2515Model) {
                "OPD2515 direct model gate failed: ${Build.MODEL}"
            }
            val release = System.getProperty("os.version", "").trim()
            require(release == Opd2515Release) {
                "OPD2515 direct kernel gate failed: $release"
            }
            val nativeDir = appContext.applicationInfo.nativeLibraryDir
            val targetRebuiltSource = File(nativeDir, "libopd2515_x9u_rebuilt_preload.so")
            val validatedSource = File(nativeDir, "libopd2515_x9u_preload.so")
            val legacySource = File(nativeDir, "libopd2515_preload.so")
            val source = when {
                targetRebuiltSource.isFile -> targetRebuiltSource
                validatedSource.isFile -> validatedSource
                else -> legacySource
            }
            require(source.isFile) { "missing OPD2515 preloader: ${source.absolutePath}" }
            val sourceHash = sha256(source).uppercase(Locale.ROOT)
            require(sourceHash in Opd2515PreloaderHashes ||
                sourceHash == Opd2515X9uPreloaderHash ||
                sourceHash == Opd2515X9uOpdRebuiltPreloaderHash) {
                "unrecognized OPD2515 preloader SHA-256: $sourceHash"
            }

            val bootId = File("/proc/sys/kernel/random/boot_id").readText().trim()
            require(bootId.isNotEmpty()) { "kernel boot_id is unavailable" }
            val bootReason = readCommandOutput("/system/bin/getprop", "ro.boot.bootreason")
            onLog(
                "<s> OPD2515 direct preflight: uid=${android.os.Process.myUid()} " +
                    "bootId=$bootId bootreason=${bootReason.ifEmpty { "unknown" }} " +
                    "preloaderSha256=$sourceHash debugDir=${debugDir ?: "none"}",
            )
            require(!isUnsafeBootReason(bootReason)) {
                "unsafe bootreason=$bootReason; reboot cleanly before retrying OPD2515"
            }

            val marker = File(filesDir, ".opd2515-direct-boot-id")
            require(!Files.isSymbolicLink(marker.toPath())) {
                "OPD2515 direct boot marker is a symbolic link"
            }
            require(!marker.exists() || marker.isFile) {
                "OPD2515 direct boot marker is not a regular file"
            }
            require(!marker.isFile || marker.readText().trim() != bootId) {
                "OPD2515 direct preloader already attempted in this boot; reboot before retrying"
            }

            val existingSu = File("/data/local/tmp/su")
            require(!Files.isSymbolicLink(existingSu.toPath())) {
                "temporary su is a symbolic link"
            }
            if (existingSu.isFile) {
                val probe = runOpd2515RootCommand(existingSu, "id")
                if (probe.code == 0 && Regex("(^|\\s)uid=0(?:\\(|\\s|$)").containsMatchIn(probe.output)) {
                    onLog("<b> OPD2515 direct preflight: temporary root is already active")
                    return@withContext 0
                }
                onLog("<s> OPD2515 direct preflight: stale su is not usable (exit=${probe.code})")
            }

            // Record the attempt before launching the kernel payload.  A
            // force-stop or a panic must never turn a second tap into a same-
            // boot retry.
            marker.writeText("$bootId\n")
            onLog("<s> OPD2515 direct preflight: attempt marker written")

            val nativeLog = File(filesDir, ".ghostlock-opd2515-direct-$bootId.log")
            if (nativeLog.exists()) require(nativeLog.delete()) { "cannot remove stale direct log" }
            val brokerLog = File(filesDir, ".ghostlock-opd2515-broker-$bootId.log")
            if (brokerLog.exists()) require(brokerLog.delete()) { "cannot remove stale broker log" }
            val ready = File(filesDir, Opd2515DirectReadyName)
            require(!Files.isSymbolicLink(ready.toPath())) {
                "OPD2515 direct ready marker is a symbolic link"
            }
            if (ready.exists()) require(ready.delete()) { "cannot remove stale root-ready marker" }
            val broker = File(filesDir, ".opd2515-direct-root-broker.sh")
            broker.writeText(
                "#!/system/bin/sh\n" +
                    "HOME_DIR=\"${filesDir.absolutePath}\"\n" +
                    "READY=\"\$HOME_DIR/$Opd2515DirectReadyName\"\n" +
                    "TMP=\"\$READY.tmp.\$\$\"\n" +
                    "if [ \"\$(id -u)\" != \"0\" ]; then exit 41; fi\n" +
                    "for name in exsystemservice com.oplus.exsystemservice; do " +
                    "for pid in \$(pidof \$name 2>/dev/null); do kill -STOP \$pid 2>/dev/null; done; " +
                    "done\n" +
                    "{ echo root=1; id; echo boot=$bootId; } >\"\$TMP\"\n" +
                    "chmod 0644 \"\$TMP\" 2>/dev/null || true\n" +
                    "mv -f \"\$TMP\" \"\$READY\"\n" +
                    "sleep 15\n",
            )
            require(broker.setReadable(true, true) && broker.setExecutable(true, true)) {
                "cannot prepare OPD2515 root broker"
            }
            val launch =
                "/system/bin/sh ${shellQuote(broker.absolutePath)} " +
                    "</dev/null >${shellQuote(brokerLog.absolutePath)} 2>&1 &"
            /* Match the validated X9U app flow: the preloader is loaded by a
             * normal system shell started from the app, and the root-side
             * broker is spawned by that same shell after the constructor has
             * obtained uid 0. */
            val command = ProcessBuilder("/system/bin/sh", "-c", launch)
                .directory(filesDir)
                .redirectErrorStream(true)
                .redirectOutput(nativeLog)
                .apply {
                    environment()["LD_PRELOAD"] = source.absolutePath
                    environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                    environment()["TMPDIR"] = filesDir.absolutePath
                    environment()["HOME"] = filesDir.absolutePath
                    environment()["GHOSTLOCK_CLIENT_UID"] =
                        android.os.Process.myUid().toString()
                }
            onLog("<b> OPD2515 direct: starting App-UID preload")
            val process = command.start()
            val finished = process.waitFor(Opd2515PreloaderTimeoutMs, TimeUnit.MILLISECONDS)
            val code = if (finished) {
                process.exitValue()
            } else {
                onLog(
                    "<s> OPD2515 direct preloader timed out after " +
                        "${Opd2515PreloaderTimeoutMs / 1000}s; terminating it",
                )
                process.destroyForcibly()
                process.waitFor(1, TimeUnit.SECONDS)
                124
            }
            val nativeBytes = runCatching { nativeLog.readBytes() }.getOrDefault(ByteArray(0))
            val nativeText = String(nativeBytes, StandardCharsets.UTF_8)
            if (nativeBytes.isNotEmpty()) {
                writeSidecar("opd2515-direct-preloader.log", nativeBytes)
                nativeText
                    .lineSequence()
                    .filter { it.isNotBlank() }
                    .forEach(onLog)
            }
            val brokerBytes = runCatching { brokerLog.readBytes() }.getOrDefault(ByteArray(0))
            if (brokerBytes.isNotEmpty()) {
                writeSidecar("opd2515-direct-broker.log", brokerBytes)
                String(brokerBytes, StandardCharsets.UTF_8)
                    .lineSequence()
                    .filter { it.isNotBlank() }
                    .forEach(onLog)
            }
            onLog("<b> OPD2515 direct preloader exited code=$code")
            /* The shell wrapper itself normally exits 0 even when a
             * constructor payload failed.  Conversely, an SELinux denial can
             * prevent the app process from executing /data/local/tmp/su even
             * after the native payload has installed a working daemon.  Use
             * the native root summary plus the root-side broker marker as the
             * handoff proof. */
            val brokerDeadline = System.currentTimeMillis() + 5_000L
            while (!ready.isFile && System.currentTimeMillis() < brokerDeadline) {
                Thread.sleep(100L)
            }
            val brokerReady = ready.isFile && ready.readText().contains("root=1")
            val nativeRootReady = nativeText.contains("direct-root-summary root=1") &&
                nativeText.contains("su=1/")
            if (!nativeRootReady) {
                return@withContext if (code == 0) 1 else code
            }
            if (!brokerReady) {
                onLog("<s> OPD2515 direct: native root proof exists but root broker marker is absent")
                return@withContext 1
            }
            onLog("<b> OPD2515 direct: root broker confirmed uid=0 and anti-root guard stop")
            0
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("<-> OPD2515 direct error: ${error::class.simpleName}: ${error.message}")
            1
        }
    }

    private fun readCommandOutput(vararg command: String): String {
        val process = ProcessBuilder(*command).redirectErrorStream(true).start()
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return ""
        }
        return process.inputStream.bufferedReader().use { it.readText().trim() }
    }

    private fun shellQuote(value: String): String =
        "'" + value.replace("'", "'\\''") + "'"

    private fun isUnsafeBootReason(reason: String): Boolean =
        reason.contains("kernel_panic", ignoreCase = true) ||
            reason.contains("malicious_app_try_to_root_devices", ignoreCase = true)

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

    private fun runOpd2515DirectPostflight(onLog: (String) -> Unit): Boolean {
        val su = File("/data/local/tmp/su")
        if (Files.isSymbolicLink(su.toPath()) || !su.isFile) {
            onLog("<s> OPD2515 direct postflight: temporary su is missing or a symlink")
            return false
        }
        val stopCommand =
            "for name in exsystemservice com.oplus.exsystemservice; " +
                "do for pid in \$(pidof \$name 2>/dev/null); do kill -STOP \$pid; " +
                "done; done"
        val stop = runOpd2515RootCommand(su, stopCommand)
        onLog("<s> OPD2515 direct postflight anti-root scan exit=${stop.code}")
        if (stop.output.isNotBlank()) onLog("<s> root postflight output: ${stop.output.trim()}")
        if (stop.code != 0) return false
        val probe = runOpd2515RootCommand(su, "id")
        onLog("<s> OPD2515 direct handoff probe exit=${probe.code} output=${probe.output.trim()}")
        return probe.code == 0 && Regex("(^|\\s)uid=0(?:\\(|\\s|$)").containsMatchIn(probe.output)
    }

    private data class Opd2515RootCommandResult(val code: Int, val output: String)

    private fun runOpd2515RootCommand(su: File, command: String): Opd2515RootCommandResult {
        val process = ProcessBuilder(su.absolutePath, "-c", command)
            .redirectErrorStream(true)
            .start()
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return Opd2515RootCommandResult(124, "timeout")
        }
        return Opd2515RootCommandResult(
            process.exitValue(),
            process.inputStream.bufferedReader().use { it.readText() },
        )
    }

    override suspend fun lastRunStuckStep(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(filesDir, RunStateFileName)
            if (!file.isFile) return@runCatching null
            RunStateCodec.parseStuckStep(file.readText())
        }.getOrNull()
    }

    private suspend fun withDebugAttackLog(
        entry: String,
        onLog: (String) -> Unit,
        run: suspend ((String) -> Unit, String?, (String, ByteArray) -> Boolean) -> Int,
    ): Int {
        val settings = debugSettings()
        if (!settings.exportEnabled) return run(onLog, null) { _, _ -> false }
        val archive = DebugAttackLog.open(appContext, entry, settings.exportLocation)
        if (archive == null) {
            onLog("<k> warning: cannot create ${settings.exportLocation} debug log")
            return run(onLog, null) { _, _ -> false }
        }
        val archivedLog: (String) -> Unit = { line ->
            runCatching { archive.append(line) }
            onLog(line)
        }
        val writeSidecar: (String, ByteArray) -> Boolean = { name, bytes ->
            runCatching { archive.writeSidecar(name, bytes) }.getOrDefault(false)
        }
        return try {
            /* First line of every archived run log: which app build produced it. */
            archivedLog(
                "<k> GhostLock ${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE} " +
                    "build ${BuildInfo.BUILD_TIME_LABEL}",
            )
            archivedLog("<k> debug log: ${archive.folderPath}/${archive.displayName}")
            archivedLog("<k> debug dump dir: ${archive.folderFile.absolutePath}")
            run(
                archivedLog,
                if (settings.kernelLogEnabled) archive.folderFile.absolutePath else null,
                writeSidecar,
            )
        } finally {
            runCatching { archive.close() }
        }
    }

    /**
     * Writes the effective runtime profile into the attempt folder: the resolved
     * HOCON (`profile.conf`) and the exact GLK1 v2 bytes handed to native
     * (`profile.bin`). No-op when debug export is disabled.
     */
    private fun dumpRuntimeProfile(
        log: (String) -> Unit,
        writeSidecar: (String, ByteArray) -> Boolean,
        release: String,
        pair: CpuPair,
        blob: ByteArray?,
    ) {
        val conf = runCatching { profileController.renderResolvedForDebug(release, pair) }.getOrNull()
        val confWritten = conf?.let {
            writeSidecar("profile.conf", it.toByteArray(StandardCharsets.UTF_8))
        } ?: false
        val blobWritten = blob?.let { writeSidecar("profile.bin", it) } ?: false
        if (confWritten || blobWritten) {
            log("<k> runtime profile written: profile.conf/profile.bin")
        }
    }

    override fun requestShizukuPermission() = shizukuRunner.requestPermission()

    override fun setShizukuStatusListener(listener: (() -> Unit)?) =
        shizukuRunner.setStatusListener(listener)

    private suspend fun runExploitBinary(
        pair: CpuPair,
        binaryName: String,
        onLog: (String) -> Unit,
        debugDir: String?,
        writeSidecar: (String, ByteArray) -> Boolean,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, binaryName)
            require(binary.isFile) { "missing native binary: ${binary.absolutePath}" }
            if (prepareKsud(workDir, onLog) != null) onLog("<k> ksud ready") else onLog("<k> warning: ksud not found")
            // U01-S14: a per-run KernelSU log path so a previous run's markers
            // can never satisfy the handoff probe; passed to the native process.
            val ksuLog = File(workDir, ksuLogName(System.currentTimeMillis()))
            val nativeLog = File(workDir, NativeLogFileName)
            nativeLog.writeText("")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            onLog(
                "<k> profile: hasProfile=${config.hasProfile} " +
                    "invalid=${config.invalidPaths.size} release=$release",
            )
            if (!config.hasProfile) {
                error(
                    "no profile matched $release; import its .conf and select it, " +
                        "or pick a built-in release",
                )
            }
            if (config.invalidPaths.isNotEmpty()) {
                error(
                    "profile has ${config.invalidPaths.size} invalid field(s): " +
                        config.invalidPaths.take(6).joinToString(),
                )
            }
            var profileBlob = profileController.nativeDocument(config)
                ?: error("profile is unavailable for $release")
            // v2: safe_mode lives in the meta section; there is no fixed slot
            // offset, so the blob is rescanned and rewritten.
            if (safeModeEnabled) {
                profileBlob = NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
            }
            dumpRuntimeProfile(onLog, writeSidecar, release, pair, profileBlob)
            val ksuOffset = AtomicLong()
            val nativeOffset = AtomicLong()
            val processRef = AtomicReference<Process?>(null)
            // tag root-script lines so they cannot be read as the native stages'
            val ksuSink: (String) -> Unit = { onLog("[ksu] $it") }
            // status events are consumed here (persisted + ACKed); plain lines are logs
            val nativeSink: (String) -> Unit = { line ->
                if (!handleStatusLine(line, processRef)) onLog(line)
            }
            val tailer = Thread {
                try {
                    while (!Thread.currentThread().isInterrupted) {
                        tailKsuLog(nativeLog, nativeOffset, nativeSink)
                        tailKsuLog(ksuLog, ksuOffset, ksuSink)
                        Thread.sleep(200)
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }.apply {
                name = "ksu-log-tailer"
                isDaemon = true
                start()
            }
            val argv = mutableListOf(
                binary.absolutePath,
                "--ghostlock-app-call",
                "--enable-status-record",
            )
            if (forceAttackTest) {
                argv += "--force-attack"
            }
            if (!debugDir.isNullOrEmpty()) {
                argv += listOf("--dump-kernel-log", debugDir)
            }
            val command = ProcessBuilder(argv)
                .directory(workDir)
                .redirectErrorStream(true)
                .redirectOutput(nativeLog)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                    environment()["TMPDIR"] = workDir.absolutePath
                    environment()["HOME"] = workDir.absolutePath
                    environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                }
            onLog("<b> starting native: ${binary.absolutePath}")
            resetRunState()
            try {
                val nativeCode = runProcess(
                    command,
                    onLog = {},
                    captureOutput = false,
                    stdin = profileBlob,
                    frameStdin = true,
                    onProcess = { processRef.set(it) },
                )
                onLog("<b> native exited code=$nativeCode")
                nativeCode
            } finally {
                withContext(Dispatchers.IO) {
                    tailer.interrupt()
                    tailer.join(1000)
                    tailKsuLog(nativeLog, nativeOffset, onLog)
                    tailKsuLog(ksuLog, ksuOffset, ksuSink)
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("<-> error: ${error::class.simpleName}: ${error.message}")
            1
        }
    }

    /** Exact target gate shared by the preloader selector and Shizuku guard. */
    private fun isOpd2515Target(release: String): Boolean =
        release == Opd2515Release && Build.MODEL.trim() == Opd2515Model

    override suspend fun readDocument(uri: String): String =
        appContext.contentResolver.openInputStream(uri.toUri())?.bufferedReader()?.use { it.readText() } ?: throw IOException("cannot open $uri")

    override suspend fun cacheDocument(uri: String, fileName: String): String {
        val target = File(filesDir, fileName)
        appContext.contentResolver.openInputStream(uri.toUri())?.use { input ->
            target.outputStream().use(input::copyTo)
        } ?: throw IOException("cannot open $uri")
        return target.absolutePath
    }

    override suspend fun userProfiles(): List<UserProfileFile> =
        withContext(Dispatchers.IO) {
            userProfileStore.list().map { stored ->
                UserProfileFile(
                    name = stored.name,
                    releases = stored.releases,
                    importedAt = stored.importedAt,
                    sizeBytes = stored.sizeBytes,
                    parseError = stored.parseError,
                    version = stored.version,
                )
            }
        }

    override suspend fun deleteUserProfile(name: String): Boolean {
        val deleted = withContext(Dispatchers.IO) { userProfileStore.delete(name) }
        if (deleted) profileController.onUserProfileDeleted(name)
        return deleted
    }

    override suspend fun renameUserProfile(name: String, newName: String): String? {
        val renamed = withContext(Dispatchers.IO) { userProfileStore.rename(name, newName) }
        if (renamed != null) profileController.onUserProfileRenamed(name, renamed)
        return renamed
    }

    /** Renders a stored document as HOCON and shares it; returns the URI. */
    override suspend fun exportUserProfile(name: String): String {
        val hocon = withContext(Dispatchers.IO) { userProfileStore.exportHocon(name) }
            ?: throw IOException("cannot export $name")
        return publishOffsets(OffsetCandidate(name.substringBeforeLast('.'), hocon))
    }

    /**
     * Converts a stored legacy document into the current layout and stores the
     * result as a new user document; returns its name, or null on failure.
     */
    override suspend fun convertUserProfile(name: String): String? {
        val hocon = withContext(Dispatchers.IO) { userProfileStore.exportHocon(name) }
            ?: return null
        val base = name.substringBeforeLast('.')
        return withContext(Dispatchers.IO) {
            userProfileStore.save("$base-converted.conf", hocon)
        }
    }

    /* ---- editing session: isolated from the live attack controller ---- */

    private var editSession: AndroidProfileConfigController? = null
    private var editSessionTargetName: String? = null
    private var editSessionTargetRelease: String? = null
    private var editSessionLive = false

    override suspend fun beginEditSession(name: String?): ProfileConfig? =
        withContext(Dispatchers.IO) {
            endEditSession()
            val deviceRelease = System.getProperty("os.version", "").orEmpty()
            val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
            /* A stored document is edited against its own release: the device
             * release would resolve the bundled profile instead and hide the
             * imported geometry. Only the live controller stays device-keyed. */
            val targetRelease = name?.let { userProfileStore.releasesOf(it).firstOrNull() }
                ?: deviceRelease
            val sessionPreferences = appContext.getSharedPreferences(
                EditSessionPreferences,
                Context.MODE_PRIVATE,
            )
            sessionPreferences.edit { clear() }
            editSessionLive = name != null && name == profileController.activeUserProfile()
            if (editSessionLive) {
                val overrides = profileController.overridesSnapshot(deviceRelease)
                if (overrides.isNotEmpty()) {
                    /* The store keeps one entry per release, so wrap it back. */
                    sessionPreferences.edit(commit = true) {
                        putString(
                            AndroidProfileConfigController.PrefDebugProfileOverrides,
                            HoconSupport.render(valueMapOf(deviceRelease to overrides)),
                        )
                    }
                }
            }
            val session = AndroidProfileConfigController(
                context = appContext,
                filesDir = filesDir,
                userProfiles = userProfileStore,
                preferences = sessionPreferences,
                forcedUserProfile = name,
                forcedBuiltinRelease = profileController.activeBuiltinRelease(),
            )
            editSession = session
            editSessionTargetName = name
            editSessionTargetRelease = targetRelease
            runCatching { session.load(targetRelease, pair) }.getOrNull()
        }

    override fun editSessionController(): ProfileConfigController? = editSession

    override fun editSessionIsLive(): Boolean = editSessionLive

    override fun editSessionTarget(): String? = editSessionTargetName

    override fun editSessionRelease(): String? = editSessionTargetRelease

    override suspend fun saveEditSessionInPlace(): Boolean = withContext(Dispatchers.IO) {
        if (editSessionLive) return@withContext false
        val session = editSession ?: return@withContext false
        val target = editSessionTargetName ?: return@withContext false
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext false
        val document = session.renderResolved(release, pair) ?: return@withContext false
        userProfileStore.overwrite(target, document)
    }

    override suspend fun commitEditSession(): Boolean = withContext(Dispatchers.IO) {
        if (!editSessionLive) return@withContext false
        val session = editSession ?: return@withContext false
        val release = System.getProperty("os.version", "").orEmpty()
        profileController.replaceOverrides(release, session.overridesSnapshot(release))
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext false
        runCatching { profileController.load(release, pair) }.isSuccess
    }

    override suspend fun saveEditSessionAsNew(): String? = withContext(Dispatchers.IO) {
        val session = editSession ?: return@withContext null
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
        val stem = (editSessionTargetName ?: release)
            .substringBeforeLast('.')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
        val name = "${stem.ifEmpty { "profile" }}-edited.conf"
        if (session.saveResolved(release, pair, name)) name else null
    }

    override suspend fun exportEditSession(): String = withContext(Dispatchers.IO) {
        val session = editSession ?: throw IOException("no editing session")
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: throw IOException("no cpu pair")
        val document = session.renderResolved(release, pair)
            ?: throw IOException("cannot render the edited profile")
        val stem = editSessionTargetName?.substringBeforeLast('.') ?: release
        publishOffsets(OffsetCandidate(stem.ifEmpty { release }, document))
    }

    override fun endEditSession() {
        editSession = null
        editSessionTargetName = null
        editSessionTargetRelease = null
        editSessionLive = false
    }

    override suspend fun publishOffsets(candidate: OffsetCandidate): String {
        val safeRelease = candidate.release.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "offsets-$safeRelease.conf")
            put(MediaStore.Downloads.MIME_TYPE, "text/plain")
        }
        val uri = appContext.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: throw IOException("cannot create download entry")
        appContext.contentResolver.openOutputStream(uri)?.use { output ->
            output.write(candidate.document.toByteArray(StandardCharsets.UTF_8))
        } ?: throw IOException("cannot open download entry")
        return uri.toString()
    }

    override fun close() {
        shizukuRunner.close()
        synchronized(processes) {
            processes.forEach(Process::destroyForcibly)
            processes.clear()
        }
    }

    /**
     * Legacy/parse helper: reads HOCON or JSON text into a list of entries.
     * Stored user documents are parsed by [UserProfileStore] instead.
     */
    private fun parseEntries(text: String): ValueList? {
        if (text.isBlank()) return null
        return try {
            when (val value = HoconSupport.parseValue(text)) {
                is List<*> -> value.asValueList()
                is Map<*, *> -> ValueList().apply { value.asValueMap()?.let(::add) }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private class PendingParsedDocument(
        val name: String,
        val text: String,
        val releases: List<String>,
        val missing: Set<String>,
    )

    /**
     * Fields a parsed profile still lacks that only an xbl_config FDT or uefi
     * memory map can fill. Used to prompt for the optional sidecars.
     */
    private fun missingSidecarFields(entries: List<ValueMap>): Set<String> =
        if (entries.isNotEmpty() && entries.all { it.getLongAt("kernel_phys_load") == null }) {
            setOf("kernel_phys_load")
        } else {
            emptySet()
        }

    private fun parsedDocumentName(releases: List<String>): String {
        val stem = releases.firstOrNull().orEmpty()
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .ifEmpty { "parsed" }
        return "$stem.conf"
    }

    private fun freshReleases(entries: List<*>): List<String> =
        entries.mapNotNull { (it.asValueMap()?.get("release") as? String) }.distinct()

    private fun isKernelSupported(): Boolean {
        val version = System.getProperty("os.version", "").orEmpty()
        if (isOpd2515Target(version) &&
            !Opd2515PreloaderValidated && !Opd2515DirectExperimental
        ) return false
        return version in builtinProfiles.unames || importedOffsetsMatch(version)
    }

    private fun importedOffsetsMatch(version: String): Boolean =
        userProfileStore.containsRelease(version)

    private fun importedOffsetsRecommendShizuku(version: String): Boolean =
        userProfileStore.recommendsShizuku(version)

    private fun buildCpuPairs() {
        cpuPairs.clear()
        cpuPairLabels.clear()
        val online = parseCpuList(readSysFile("/sys/devices/system/cpu/online"))
        online.groupBy { readMaxFreq(it) }.filterKeys { it > 0 }.toSortedMap(compareByDescending { it }).forEach { (freq, cluster) ->
                cluster.sorted().chunked(2).filter { it.size == 2 }.forEach { pair ->
                    cpuPairs += CpuPair(pair[0], pair[1])
                    cpuPairLabels += "${pair[0]},${pair[1]} · ${formatFreq(freq)}"
                }
            }
        if (CpuPair(0, 1) !in cpuPairs) {
            cpuPairs += CpuPair(0, 1)
            val freq = readMaxFreq(0)
            cpuPairLabels += "0,1" + if (freq > 0) " · ${formatFreq(freq)}" else ""
        }
    }

    private fun restoreCpuPair() {
        val saved = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).getString("cpu_pair", null) ?: return
        val pair = saved.split(',').mapNotNull { it.trim().toIntOrNull() }
        if (pair.size == 2) cpuPairs.indexOf(CpuPair(pair[0], pair[1])).takeIf { it >= 0 }?.let { selectedCpuPair = it }
    }

    private fun restoreShizukuPreference() {
        val prefs = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
        shizukuPreferenceSet = prefs.getBoolean("shizuku_explicit", false)
        shizukuEnabled = prefs.getBoolean("shizuku_enabled", false)
    }

    private fun restoreForceAttackTest() {
        forceAttackTest = preferences.getBoolean(PrefForceAttackTest, false)
    }

    private fun parseCpuList(value: String): List<Int> = value.split(',').flatMap { part ->
        val range = part.trim().split('-').mapNotNull { it.toIntOrNull() }
        when (range.size) {
            1 -> range
            2 -> (range[0]..range[1]).toList()
            else -> emptyList()
        }
    }

    private fun readMaxFreq(cpu: Int): Long = readSysFile("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").toLongOrNull() ?: -1L

    private fun formatFreq(khz: Long): String =
        if (khz >= 1_000_000L) "%.2f GHz".format(Locale.ROOT, khz / 1_000_000.0) else "%.0f MHz".format(Locale.ROOT, khz / 1000.0)

    private fun readSysFile(path: String): String = File(path).takeIf { it.isFile }?.useLines { it.firstOrNull()?.trim().orEmpty() } ?: ""

    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    private fun validDeviceName(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

    private fun resolveDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty()
        val marketName = when (manufacturer.lowercase(Locale.ROOT)) {
            "xiaomi" -> firstValidProperty("ro.product.marketname")
            "oppo", "oneplus", "realme", "oplus" -> {
                val cn = Locale.getDefault().country.equals("CN", true)
                firstValidProperty(
                    *(if (cn) arrayOf(
                        "ro.vendor.oplus.market.name", "ro.vendor.oplus.market.enname"
                    ) else arrayOf("ro.vendor.oplus.market.enname", "ro.vendor.oplus.market.name"))
                )
            }

            "vivo" -> firstValidProperty("ro.vivo.market.name")
            "honor", "huawei" -> firstValidProperty("ro.config.marketing_name")
            "zte", "nubia" -> firstValidProperty("ro.vendor.product.ztename")
            else -> null
        }
        return marketName ?: listOfNotNull(
            manufacturer, Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) }, Build.MODEL.orEmpty()
        ).filter { it.isNotBlank() }.joinToString(" ")
    }

    private fun resolveSocName(): String = listOf(
        systemProperty("ro.soc.manufacturer"),
        systemProperty("ro.soc.model"),
    ).mapNotNull(::validDeviceName).joinToString(" ").ifBlank { "unknown" }

    private fun firstValidProperty(vararg keys: String): String? = keys.asSequence().firstNotNullOfOrNull { validDeviceName(systemProperty(it)) }

    private fun prepareKsud(workDir: File, onLog: (String) -> Unit): File? {
        val packages = listOf("me.weishu.kernelsu.pr", "me.weishu.kernelsu", "com.resukisu.resukisu", "com.kowx712.supermanager")
        var installed = false
        for (packageName in packages) {
            val appInfo = runCatching { appContext.packageManager.getApplicationInfo(packageName, 0) }.getOrNull() ?: continue
            installed = true
            val source = File(appInfo.nativeLibraryDir, "libksud.so")
            if (!source.isFile) continue
            val output = File(workDir, "ksud")
            runCatching {
                source.inputStream().use { input -> output.outputStream().use { input.copyTo(it) } }
                runCatching { Os.chmod(output.absolutePath, 448) }
                return output
            }.onFailure { onLog("<k> copy ksud failed: ${it.message}") }
        }
        if (!installed) onLog("<k> KernelSU/ReSukiSU/KowSU app not installed")
        return null
    }

    private suspend fun runProcess(
        builder: ProcessBuilder,
        onLog: (String) -> Unit = {},
        timeoutSeconds: Long = 300,
        captureOutput: Boolean = true,
        stdin: ByteArray? = null,
        frameStdin: Boolean = false,
        onProcess: ((Process) -> Unit)? = null,
    ): Int = runInterruptible {
        val process = builder.start()
        synchronized(processes) { processes += process }
        if (stdin != null) {
            if (frameStdin) {
                /* 4-byte big-endian length + payload, stdin kept open for the
                 * status-record ACK channel. */
                runCatching {
                    val out = process.outputStream
                    val length = stdin.size
                    out.write(
                        byteArrayOf(
                            (length ushr 24).toByte(),
                            (length ushr 16).toByte(),
                            (length ushr 8).toByte(),
                            length.toByte(),
                        ),
                    )
                    out.write(stdin)
                    out.flush()
                }
            } else {
                runCatching { process.outputStream.use { it.write(stdin) } }
            }
        }
        onProcess?.invoke(process)
        val reader = if (captureOutput) Thread {
            try {
                process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines -> lines.forEach(onLog) }
            } catch (_: IOException) {
            }
        }.apply {
            name = "process-output-reader"
            isDaemon = true
        } else null
        try {
            reader?.start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            reader?.let(::joinReader)
            if (finished) process.exitValue() else -1
        } finally {
            if (process.isAlive) process.destroyForcibly()
            reader?.interrupt()
            runCatching { process.inputStream.close() }
            reader?.let(::joinReader)
            synchronized(processes) { processes -= process }
        }
    }

    private fun joinReader(reader: Thread) {
        try {
            reader.join(3000)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun tailKsuLog(logFile: File, offset: AtomicLong, onLog: (String) -> Unit) {
        if (!logFile.isFile) return
        synchronized(offset) {
            runCatching {
                RandomAccessFile(logFile, "r").use { file ->
                    val position = offset.get().takeIf { it <= file.length() } ?: 0L
                    file.seek(position)
                    var lastComplete = position
                    val pending = StringBuilder()
                    while (true) {
                        val byte = file.read()
                        if (byte == -1) break
                        if (byte == '\n'.code) {
                            if (pending.isNotEmpty()) onLog(pending.toString())
                            pending.clear()
                            lastComplete = file.filePointer
                        } else {
                            pending.append(byte.toChar())
                        }
                    }
                    offset.set(lastComplete)
                }
            }
        }
    }

    private val processes = mutableSetOf<Process>()

}
