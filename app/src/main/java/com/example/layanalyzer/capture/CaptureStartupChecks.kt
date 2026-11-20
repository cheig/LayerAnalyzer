// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import com.example.layanalyzer.BuildConfig

/** In-process instrumentation seam, with no Intent, preference or JNI entry.
 * Release never invokes the observer. Checkpoints follow ownership transfer so
 * a thrown failure exercises the same finally blocks as a real startup error.
 */
internal object CaptureStartupChecks {
    @Volatile internal var observer: ((String) -> Unit)? = null

    fun reached(stage: String) {
        if (BuildConfig.DEBUG) observer?.invoke(stage)
    }
}
