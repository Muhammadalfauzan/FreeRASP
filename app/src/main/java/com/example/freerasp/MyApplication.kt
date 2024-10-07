package com.example.freerasp

import android.app.Application
import android.util.Log
import com.aheaditec.talsec_security.security.api.SuspiciousAppInfo
import com.aheaditec.talsec_security.security.api.Talsec
import com.aheaditec.talsec_security.security.api.TalsecConfig
import com.aheaditec.talsec_security.security.api.ThreatListener

class MyApplication : Application (), ThreatListener.ThreatDetected {

    override fun onCreate() {
        super.onCreate()
        val expectedPackageName = "com.example.freerasp"
        val expectedSigningCertificateHashBase64 = arrayOf(
            "yeibC16Pjpx6pv0OwRIYmH/Xd8djN/a/zDOo/CEKito="
        )
        val isProd = true

        val config = TalsecConfig.Builder(
            expectedPackageName,
            expectedSigningCertificateHashBase64
        )
            .prod(isProd)
            .build()

        ThreatListener(this).registerListener(this)
        Talsec.start(this, config)

    }

    override fun onRootDetected() {
        Log.e("ThreatListener", "Root Detected!")
        // showToast("Root Access Detected! The app might be at risk.")
    }

    override fun onDebuggerDetected() {
        Log.e("ThreatListener", "Debugger Detected!")
        // showToast("Debugger Detected! Please remove it to continue.")
    }

    override fun onEmulatorDetected() {
        Log.e("ThreatListener", "Emulator Detected!")
        // showToast("Emulator Environment Detected!")
    }

    override fun onTamperDetected() {
        Log.e("ThreatListener", "Tampering Detected!")
        /* showToast("The app has been tampered with. It might not be secure.")*/
    }

    override fun onUntrustedInstallationSourceDetected() {
        Log.e("ThreatListener", "Untrusted Installation Source Detected!")
        /* showToast("The app was installed from an untrusted source.")*/
    }

    override fun onHookDetected() {
        Log.e("ThreatListener", "Hook Detected!")
        /* showToast("Hooking framework detected! The app might be compromised.")*/
    }

    override fun onDeviceBindingDetected() {
        Log.e("ThreatListener", "Device Binding Detected!")
        /* showToast("Device binding security violation detected.")*/
    }

    override fun onObfuscationIssuesDetected() {
        Log.e("ThreatListener", "Obfuscation Issues Detected!")
        /*showToast("Obfuscation issues detected! The app might be at risk.")*/
    }

    override fun onMalwareDetected(maliciousApps: MutableList<SuspiciousAppInfo>?) {
        Log.e("ThreatListener", "Malware Detected!")
        /* showToast("Malware Detected! Potential malicious apps installed.")*/
    }
}