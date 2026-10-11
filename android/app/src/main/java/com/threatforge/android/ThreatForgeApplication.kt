package com.threatforge.android

import android.app.Application
import com.threatforge.android.pipeline.DetectionPipeline

class ThreatForgeApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        instance = this
        isInitialized = true
    }

    companion object {
        lateinit var instance: ThreatForgeApplication
            private set

        var isInitialized: Boolean = false
            private set

        val pipeline: DetectionPipeline by lazy {
            DetectionPipeline()
        }
    }
}
