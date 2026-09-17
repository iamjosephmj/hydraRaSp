package redteam.full

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File

/**
 * red-team LSPosed module (research only), scoped to com.example.hydrasample.
 *
 * Two jobs:
 *
 *  1. [hookOrchestrator] — `io.ssemaj.dx.K.o()` -> 0, so the native detector sweep never
 *     runs. Nothing is detected, so nothing latches a failure and the in-process kill
 *     path is never entered.
 *
 *  2. [loadNative] — loads the native half, which arms fault handlers AND recovers the
 *     gated key *dynamically*.
 *
 *     `K.g` normally blocks in `0x66378` waiting on unlock material that `0x65b24`
 *     publishes only after a clean sweep; with the sweep skipped that never happens and
 *     the UI sits on its "🔒 …" placeholder forever. Rather than reimplementing the key
 *     derivation here, the native half calls the runtime's own `0x65b24` to publish the
 *     material, and the genuine native `K.g()` then derives and returns the real key
 *     itself. No key schedule, no domain strings and no ciphertext live in this module —
 *     the runtime is simply persuaded to open its own gate.
 */
class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    override fun initZygote(sp: IXposedHookZygoteInit.StartupParam) {
        modulePath = sp.modulePath
    }


    override fun handleLoadPackage(lp: XC_LoadPackage.LoadPackageParam) {
        if (lp.packageName != TARGET) return
        XposedBridge.log("$TAG loaded for ${lp.packageName}")
        loadNative()
        hookOrchestrator(lp)
    }

    /**
     * Load the native half, which arms fault handlers that retire hydra's in-process
     * executioner threads. Zygisk injection did not work on this rig (Magisk 30.7 never
     * maps a plain zygisk/<abi>.so module), so the library rides in with this module and
     * is dlopen'd from the module APK's extracted lib dir.
     */
    private fun loadNative() {
        val base = modulePath?.substringBeforeLast('/') ?: run {
            XposedBridge.log("$TAG no modulePath; native half not loaded"); return
        }
        for (abi in listOf("arm64", "arm64-v8a")) {
            val p = "$base/lib/$abi/libfullbypass.so"
            if (File(p).exists()) {
                runCatching { System.load(p) }
                    .onSuccess { XposedBridge.log("$TAG native half loaded from $p") }
                    .onFailure { XposedBridge.log("$TAG System.load($p) failed: ${it.message}") }
                return
            }
        }
        XposedBridge.log("$TAG libfullbypass.so not found under $base/lib")
    }

    /** Skip the whole native sweep at its entry point. */
    private fun hookOrchestrator(lp: XC_LoadPackage.LoadPackageParam) {
        runCatching {
            XposedHelpers.findAndHookMethod(
                ANCHOR, lp.classLoader, "o",
                XC_MethodReplacement.returnConstant(0),
            )
            XposedBridge.log("$TAG hooked $ANCHOR.o() -> 0 (sweep skipped)")
        }.onFailure { XposedBridge.log("$TAG hookOrchestrator failed: ${it.message}") }
    }

    private companion object {
        @Volatile var modulePath: String? = null
        const val TARGET = "com.example.hydrasample"
        const val TAG = "[di-rt-full]"
        const val ANCHOR = "io.ssemaj.dx.K"
    }
}
