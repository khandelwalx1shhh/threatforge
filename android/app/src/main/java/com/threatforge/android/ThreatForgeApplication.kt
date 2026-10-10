package com.threatforge.android

import android.app.Application
import com.threatforge.android.pipeline.DetectionPipeline

class ThreatForgeApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    companion object {
        lateinit var instance: ThreatForgeApplication
            private set

        val pipeline: DetectionPipeline by lazy {
            DetectionPipeline()
        }
    }
}
