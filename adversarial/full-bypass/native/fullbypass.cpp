// full-bypass native half — red-team, research only.
//
// Loaded into com.example.hydrasample by the LSPosed module (see MainHook.kt), which
// is the injection path already proven to work on this rig. A constructor arms fault
// handlers as soon as the library is dlopen'd.
//
// Purpose: retire hydra's *in-process* executioner threads.
//
// With `debug.di.wdtest=loop` set, the forked watchdog child exits before arming, so
// both external kills are gone — the ptrace register corruption and the 30-heartbeat
// completion-deadline SIGKILL. Neither is defeatable from inside the process (SIGKILL
// is uncatchable; the ptrace kill runs in another process). What is left is in-process
// and therefore catchable:
//
//   * 0x330c8 timed-death fallback     -> faults at 0x3323c  (~2.3s after a failed sweep)
//   * 0x311fc watchdog-monitor failure -> faults at 0x312f0  (~10s, 4 failed heartbeats)
//
// Both are wild-address stores inside a flattened loop, so returning from the handler
// just re-faults on the next iteration. Instead we identify the faulting thread as an
// executioner — the fault PC lies inside libdicore.so's executable mapping — and park
// that thread permanently. The rest of the process is untouched.
//
// Faults anywhere else are restored to SIG_DFL and re-raised, so unrelated crashes are
// not masked.

#include <initializer_list>
#include <android/log.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ucontext.h>
#include <link.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "di-rt-native", __VA_ARGS__)

namespace {

uintptr_t g_lo = 0, g_hi = 0;
uintptr_t g_bias = 0;          // libdicore load bias; file offsets are image-base 0
volatile sig_atomic_t g_parked = 0;

int phdr_cb(struct dl_phdr_info *info, size_t, void *) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libdicore.so")) return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        g_bias = static_cast<uintptr_t>(info->dlpi_addr);
        g_lo = g_bias + static_cast<uintptr_t>(ph->p_vaddr);
        g_hi = g_lo + static_cast<uintptr_t>(ph->p_memsz);
        return 1;
    }
    return 0;
}

// libdicore.so is mapped straight out of base.apk, so /proc/self/maps shows the APK
// path and never the soname. dl_iterate_phdr walks the linker's in-memory link_map,
// which carries the real soname either way.
bool find_dicore_range() {
    return dl_iterate_phdr(phdr_cb, nullptr) == 1 && g_lo != 0;
}

void on_fault(int sig, siginfo_t *info, void *uctx) {
    auto *uc = static_cast<ucontext_t *>(uctx);
#if defined(__aarch64__)
    uintptr_t pc = static_cast<uintptr_t>(uc->uc_mcontext.pc);
#elif defined(__arm__)
    uintptr_t pc = static_cast<uintptr_t>(uc->uc_mcontext.arm_pc);
#else
    uintptr_t pc = 0;
#endif
    if (g_lo && pc >= g_lo && pc < g_hi) {
        g_parked++;
        LOG("parked executioner thread: sig=%d pc=libdicore+0x%lx addr=%p [parked=%ld]",
            sig, (unsigned long)(pc - g_lo), info ? info->si_addr : nullptr, (long)g_parked);
        for (;;) pause();          // thread retired; never returns
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

void install_handlers() {
    static char altstack[SIGSTKSZ * 4];
    stack_t ss{};
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);

    struct sigaction sa{};
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (int s : {SIGSEGV, SIGBUS}) sigaction(s, &sa, nullptr);
    LOG("armed: libdicore RX=[0x%lx,0x%lx)", (unsigned long)g_lo, (unsigned long)g_hi);
}

// Offset of the runtime's own "publish unlock material" routine, image base 0.
// 0x64790 (arm-clean-runtime) is just:
//     FUN_00165b24();          <- publishes the 32-byte unlock material + signals waiters
//     FUN_00165014();          <- arms the epoch observation
//     pthread_once(..., 0x647b8);  <- starts the periodic re-sweep thread
// We call only the first. K.g() -> 0x55238 -> 0x66378 is blocked on exactly that
// material; once it is published the genuine native K.g returns the real key, derived
// by the runtime's own code. We deliberately skip the other two so no epoch is armed
// and no periodic sweep thread is started.
constexpr uintptr_t kPublishUnlock = 0x65b24;   // void(void)

void publish_unlock() {
    if (!g_bias) return;
    auto fn = reinterpret_cast<void (*)()>(g_bias + kPublishUnlock);
    LOG("calling publish-unlock at libdicore+0x%lx", (unsigned long)kPublishUnlock);
    fn();
    LOG("unlock material published; native K.g() can now return the real key");
}

void *setup(void *) {
    // libdicore is loaded by System.loadLibrary; poll until its mapping appears.
    for (int i = 0; i < 1200; i++) {
        if (find_dicore_range()) {
            install_handlers();   // arm first, so a fault inside publish_unlock is contained
            publish_unlock();
            return nullptr;
        }
        usleep(25 * 1000);
    }
    LOG("libdicore.so mapping never appeared; handlers not armed");
    return nullptr;
}

__attribute__((constructor)) void init() {
    LOG("native half loaded into pid=%d", getpid());
    pthread_t t;
    if (pthread_create(&t, nullptr, setup, nullptr) == 0) pthread_detach(t);
}

}  // namespace
