package com.ghostlock.app.data.route

/** `route.result_stack` geometry used by the OPD2515 pselect result-copy path. */
data class ResultConfig(
    val waiterShift: Int?,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        waiterShift?.let { add("waiter_shift" to it.toLong().toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_shift" -> copy(waiterShift = value.toLong().toInt())
        else -> this
    }

    companion object {
        val EMPTY = ResultConfig(null)

        fun from(value: (String) -> Long?): ResultConfig = ResultConfig(
            waiterShift = value("pselect_waiter_shift")?.toInt(),
        )
    }
}
