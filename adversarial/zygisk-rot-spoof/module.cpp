// zygisk-rot-spoof — red-team module — research / transparency ONLY. Inert against
// every app but the Raven sample (io.ssemaj.raven.sample).
//
// GOAL: spoof the "SelfSigned (yellow)" part of the hardware key-attestation
// RootOfTrust that DeviceIntelligence's attestation_stage reads, WITHOUT a keybox
// and WITHOUT touching libdicore's .text. The RASP's on-device chain check is
// STRUCTURAL (DN-chain to a pinned Google root, no signatures — see
// attest_verdict.cpp), so flipping the leaf's verifiedBootState ENUMERATED byte
// (SelfSigned 0x01 -> Verified 0x00) in the DER is enough to make kd.bs read
// Verified => bootcode 110 (VALID+fresh+Verified). That evades the primary bad-boot
// kill (bootlow 11/12/13) and drops the device into the anti-spoof correlation
// block. The whole point of this module is the EMPIRICAL question: does the RASP
// then catch us anyway (runtime_hooking_present / cross-level / device-property)?
//
// MECHANISM: the RASP obtains the attestation chain via a native keystore2 binder
// call. Every binder round-trip is an ioctl(fd, BINDER_WRITE_READ, ...). We GOT-hook
// ioctl in the loaded ELF objects (no .text write => native text-hash self-integrity
// is untouched), let the real call run, then scan the reply buffer for the Android
// Key Attestation extension and flip verifiedBootState inside the RootOfTrust [704].
//
// modes (adb shell setprop hydra.rot.mode <mode>) — default bs:
//   off   — hook installed but pass-through (baseline: confirm we changed nothing)
//   bs    — flip verifiedBootState SelfSigned/Unverified/Failed -> Verified(0)
//   full  — bs + force deviceLocked TRUE + zero verifiedBootKey (mimic green/Google)
// Scoped to io.ssemaj.raven.sample; every other process unloads the module.

#include <sys/types.h>
#include "zygisk.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#define TARGET "io.ssemaj.raven.sample"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "DI-ROT-SPOOF", __VA_ARGS__)

// BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read); 64-bit struct is 0x30.
#ifndef BINDER_WRITE_READ
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read_local)
#endif
struct binder_write_read_local {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size, read_consumed, read_buffer;
};

namespace {

// ---- config ---------------------------------------------------------------
enum Mode { OFF, BS, FULL };
volatile int g_mode = BS;
volatile long g_flips = 0;

int read_mode() {
    char m[PROP_VALUE_MAX] = {0};
    if (__system_property_get("hydra.rot.mode", m) <= 0) return BS;
    if (!strcmp(m, "off"))  return OFF;
    if (!strcmp(m, "full")) return FULL;
    return BS;
}

using ioctl_t = int (*)(int, unsigned long, ...);
ioctl_t g_real_ioctl = nullptr;

// ---- DER helpers: walk one TLV. Returns pointer past the value, or nullptr. ---
// Fills *hdr (bytes of tag+len), *len (content length), *tag.
const uint8_t* tlv(const uint8_t* p, const uint8_t* end, int* tag, size_t* len, const uint8_t** val) {
    if (p >= end) return nullptr;
    const uint8_t* s = p;
    int t = *p++;
    if ((t & 0x1f) == 0x1f) {                 // high-tag-number form (context [704] etc.)
        t = 0;
        while (p < end && (*p & 0x80)) p++;    // (we only need to skip; caller matches raw bytes)
        if (p < end) p++;
        t = -1;                                // "multibyte" sentinel; callers match by raw prefix
        (void)s;
    }
    if (p >= end) return nullptr;
    size_t l = *p++;
    if (l & 0x80) {
        int n = l & 0x7f;
        if (n == 0 || n > 4 || p + n > end) return nullptr;
        l = 0;
        for (int i = 0; i < n; i++) l = (l << 8) | *p++;
    }
    if (p + l > end) return nullptr;
    if (tag) *tag = t;
    if (len) *len = l;
    if (val) *val = p;
    return p + l;
}

// Find the RootOfTrust context tag [704] == raw bytes BF 85 40, then flip the
// verifiedBootState ENUMERATED and (in FULL) deviceLocked + verifiedBootKey.
// Returns number of RootOfTrust structures edited in this buffer.
int spoof_rot_in_buffer(uint8_t* buf, size_t n, int mode) {
    static const uint8_t ROT[3] = {0xBF, 0x85, 0x40};   // context-explicit [704]
    int edits = 0;
    for (size_t i = 0; i + 8 < n; i++) {
        if (buf[i] != ROT[0] || buf[i+1] != ROT[1] || buf[i+2] != ROT[2]) continue;
        const uint8_t* p = buf + i + 3;
        const uint8_t* end = buf + n;
        // [704] length
        size_t rot_len = 0; const uint8_t* rot_val = nullptr;
        // read length of the explicit wrapper
        { size_t l = *p++; if (l & 0x80) { int k=l&0x7f; if(k<1||k>4||p+k>end) continue; l=0; for(int j=0;j<k;j++) l=(l<<8)|*p++; } rot_len=l; rot_val=p; }
        if (rot_val + rot_len > end) continue;
        // inside: SEQUENCE
        int t; size_t sl; const uint8_t* sv;
        const uint8_t* q = tlv(rot_val, rot_val + rot_len, &t, &sl, &sv);
        if (!q || sv == nullptr) continue;
        const uint8_t* seq = sv; const uint8_t* seq_end = sv + sl;
        // field 1: verifiedBootKey OCTET STRING (0x04)
        const uint8_t* f1v; size_t f1l; int f1t;
        const uint8_t* r = tlv(seq, seq_end, &f1t, &f1l, &f1v);
        if (!r) continue;
        // field 2: deviceLocked BOOLEAN (0x01, len 1)
        const uint8_t* f2v; size_t f2l; int f2t;
        const uint8_t* r2 = tlv(r, seq_end, &f2t, &f2l, &f2v);
        if (!r2) continue;
        // field 3: verifiedBootState ENUMERATED (0x0A, len 1)
        const uint8_t* f3v; size_t f3l; int f3t;
        const uint8_t* r3 = tlv(r2, seq_end, &f3t, &f3l, &f3v);
        if (!r3 || f3l != 1) continue;
        uint8_t* state = const_cast<uint8_t*>(f3v);
        if (mode != OFF && *state != 0x00) {
            LOG("RootOfTrust @%zu: verifiedBootState %u -> 0 (Verified); deviceLocked=%u",
                i, *state, (f2l == 1 ? f2v[0] : 255));
            *state = 0x00;                         // SelfSigned/Unverified/Failed -> Verified
            edits++;
        }
        if (mode == FULL) {
            if (f2t == 0x01 && f2l == 1) *const_cast<uint8_t*>(f2v) = 0xFF;   // deviceLocked = TRUE
            if (f1t == 0x04 && f1l > 0) memset(const_cast<uint8_t*>(f1v), 0, f1l); // key -> zero (Google/green)
        }
    }
    return edits;
}

// ---- our ioctl: run real, then post-process binder replies ----------------
int hooked_ioctl(int fd, unsigned long request, void* arg) {
    int rc = g_real_ioctl(fd, request, arg);
    if (request == (unsigned long)BINDER_WRITE_READ && arg && g_mode != OFF) {
        auto* bwr = reinterpret_cast<binder_write_read_local*>(arg);
        if (bwr->read_consumed > 0 && bwr->read_buffer) {
            uint8_t* rb = reinterpret_cast<uint8_t*>(bwr->read_buffer);
            int e = spoof_rot_in_buffer(rb, (size_t)bwr->read_consumed, g_mode);
            if (e) g_flips += e;
        }
    }
    return rc;
}

// ---- GOT hook: patch the `ioctl` JUMP_SLOT in every loaded ELF object ------
struct IterCtx { void* replace; void** saved_one; };

int patch_got_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* ctx = reinterpret_cast<IterCtx*>(data);
    const char* name = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(name, "libdicore")) return 0;      // never hook inside the RASP itself
    if (strstr(name, "rot")) return 0;            // or ourselves

    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
            dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
    if (!dyn) return 0;

    const char* strtab = nullptr; const ElfW(Sym)* symtab = nullptr;
    const uint8_t* jmprel = nullptr; size_t pltrelsz = 0, relaent = sizeof(ElfW(Rela));
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_STRTAB:  strtab = reinterpret_cast<const char*>(d->d_un.d_ptr); break;
            case DT_SYMTAB:  symtab = reinterpret_cast<const ElfW(Sym)*>(d->d_un.d_ptr); break;
            case DT_JMPREL:  jmprel = reinterpret_cast<const uint8_t*>(d->d_un.d_ptr); break;
            case DT_PLTRELSZ:pltrelsz = d->d_un.d_val; break;
            case DT_RELAENT: relaent = d->d_un.d_val; break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return 0;

    long pg = sysconf(_SC_PAGESIZE);
    for (size_t off = 0; off < pltrelsz; off += relaent) {
        auto* rela = reinterpret_cast<const ElfW(Rela)*>(jmprel + off);
        uint32_t symidx = ELF64_R_SYM(rela->r_info);
        const char* sname = strtab + symtab[symidx].st_name;
        if (strcmp(sname, "ioctl") != 0) continue;
        auto* slot = reinterpret_cast<void**>(info->dlpi_addr + rela->r_offset);
        void* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(slot) & ~(uintptr_t)(pg - 1));
        if (mprotect(page, pg, PROT_READ | PROT_WRITE) != 0) continue;
        if (*ctx->saved_one == nullptr) *ctx->saved_one = *slot;   // capture real ioctl once
        *slot = ctx->replace;
        mprotect(page, pg, PROT_READ);
        LOG("GOT-hooked ioctl in %s", name[0] ? name : "(exe)");
    }
    return 0;
}

void* spoof_thread(void*) {
    g_mode = read_mode();
    // resolve real ioctl (fallback if no GOT slot captured)
    g_real_ioctl = reinterpret_cast<ioctl_t>(dlsym(RTLD_DEFAULT, "ioctl"));

    // wait until the RASP lib is mapped so we hook AFTER the loader settled.
    for (int i = 0; i < 3000; i++) {
        void* h = dlopen("libdicore.so", RTLD_NOLOAD | RTLD_NOW);
        if (h) break;
        usleep(2000);
    }
    void* saved = nullptr;
    IterCtx ctx{ reinterpret_cast<void*>(&hooked_ioctl), &saved };
    dl_iterate_phdr(patch_got_cb, &ctx);
    if (saved) g_real_ioctl = reinterpret_cast<ioctl_t>(saved);
    LOG("installed. mode=%d real_ioctl=%p — waiting for attestation binder traffic", g_mode, (void*)g_real_ioctl);

    // keep refreshing mode + re-hook any late-loaded libs for a while.
    for (int i = 0; i < 4000; i++) {
        g_mode = read_mode();
        dl_iterate_phdr(patch_got_cb, &ctx);
        usleep(5000);
        if (i % 200 == 0 && g_flips) LOG("cumulative RootOfTrust edits: %ld", g_flips);
    }
    LOG("spoof thread exiting; total RootOfTrust edits=%ld", g_flips);
    return nullptr;
}

}  // namespace

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ModuleBase;

class RotSpoof : public ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override { api_ = api; env_ = env; }
    void preAppSpecialize(AppSpecializeArgs* args) override {
        target_ = false;
        if (!args || !args->nice_name) return;
        char want[PROP_VALUE_MAX] = {0};
        if (__system_property_get("hydra.rot.target", want) <= 0) strcpy(want, TARGET);
        const char* n = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (n) { target_ = !strcmp(n, want); env_->ReleaseStringUTFChars(args->nice_name, n); }
        if (!target_) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (!target_) return;
        pthread_t t;
        if (pthread_create(&t, nullptr, spoof_thread, nullptr) == 0) pthread_detach(t);
    }
private:
    Api* api_ = nullptr; JNIEnv* env_ = nullptr; bool target_ = false;
};

REGISTER_ZYGISK_MODULE(RotSpoof)
