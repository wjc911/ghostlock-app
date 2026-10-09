package com.ghostlock.app.boot

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.ComponentName
import android.content.Intent
import android.util.Log
import rikka.shizuku.Shizuku
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Best-effort bridge for the OPPO boot-order quirk.
 *
 * Shizuku already owns WRITE_SECURE_SETTINGS and its exported boot receiver
 * contains the complete ADB-key/mDNS startup implementation.  Reusing that
 * receiver avoids duplicating credentials or pretending that an ordinary APK
 * can become UID 2000.  Android may reject a protected broadcast from an app;
 * that is caught and logged, leaving the device in the safe manual-start
 * state.  There is no exploit or native payload on this path.
 */
class ShizukuBootRelayJobService : JobService() {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val cancelled = AtomicBoolean(false)

    override fun onStartJob(params: JobParameters): Boolean {
        cancelled.set(false)
        executor.execute {
            val result = runCatching {
                if (cancelled.get() || Shizuku.pingBinder()) {
                    "already-running"
                } else if (!packageManager.isPackageInstalled(SHIZUKU_PACKAGE)) {
                    "shizuku-not-installed"
                } else {
                    val intent = Intent(Intent.ACTION_BOOT_COMPLETED).apply {
                        component = ComponentName(
                            SHIZUKU_PACKAGE,
                            SHIZUKU_BOOT_RECEIVER,
                        )
                        addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                    }
                    sendBroadcast(intent)
                    "broadcast-sent"
                }
            }.getOrElse { error ->
                Log.w(TAG, "post-boot Shizuku relay failed", error)
                "failed:${error.javaClass.simpleName}"
            }
            Log.i(TAG, "post-boot Shizuku relay result=$result")
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        cancelled.set(true)
        return false
    }

    override fun onDestroy() {
        cancelled.set(true)
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun android.content.pm.PackageManager.isPackageInstalled(packageName: String): Boolean =
        runCatching {
            getApplicationInfo(packageName, 0)
            true
        }.getOrDefault(false)

    companion object {
        const val JOB_ID = 0x474c42
        private const val TAG = "GhostLockBootRelay"
        private const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        private const val SHIZUKU_BOOT_RECEIVER =
            "moe.shizuku.manager.receiver.BootCompleteReceiver"
    }
}
