package com.ghostlock.app.boot

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Schedules one network-aware retry of Shizuku's own start-on-boot path.
 *
 * OPPO sends LOCKED_BOOT_COMPLETED before Wi-Fi is usable.  Shizuku's
 * receiver therefore exits before it can turn on wireless ADB.  The relay is
 * deliberately tiny and passive: it never starts GhostLock's native code and
 * it never writes secure settings.  It only asks the platform to run the
 * companion job once a network is available.
 */
class BootRelayReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> Unit

            else -> return
        }

        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
        val job = JobInfo.Builder(
            ShizukuBootRelayJobService.JOB_ID,
            ComponentName(context, ShizukuBootRelayJobService::class.java),
        )
            // NETWORK_TYPE_ANY is important here: OPPO may expose Wi-Fi only
            // after the locked-boot broadcast, and metered networks are valid.
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setMinimumLatency(MIN_DELAY_MS)
            .build()
        val result = runCatching { scheduler.schedule(job) }.getOrDefault(JobScheduler.RESULT_FAILURE)
        Log.i(TAG, "post-boot Shizuku relay scheduled action=${intent.action} result=$result")
    }

    companion object {
        private const val TAG = "GhostLockBootRelay"
        private const val MIN_DELAY_MS = 1_000L
    }
}
