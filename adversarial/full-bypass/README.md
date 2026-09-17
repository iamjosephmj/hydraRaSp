# `full-bypass` — the sample runs, unkilled, with every gated secret in plaintext

**Result:** `com.example.hydrasample` survives indefinitely on a rooted device, nothing
detects the tamper, and all three sweep-gated values render decrypted.

Measured on Pixel 8a / Android 17 / Magisk 30.7 (`30700`) / Vector (LSPosed fork) 3080,
arm64. Artifact SHA-256 `51099311b15eade3a38f005891e6ad4178c16669c3b3ed5cd3c75fb68b160e87`.

```
t=0s   alive pid=9490 9549
t=61s  alive pid=9490 9790      <- past the watchdog completion deadline
t=234s alive pid=9490 10318
=== SURVIVED 240s ===
```

```
🔓 apiUrl       https://api.your-backend.example/v1
🔓 apiKey       sk_live_sample_abc123
🔓 config.json  {"feature_flags":{...},"api_base":"https://api.your-backend.example/v1",...}
```

## The three layers, and what defeats each

| Layer | Enforcement | Defeated by |
|---|---|---|
| detection funnel | `K.o()` runs the sweep; root is found; failure latches | LSPosed hook: `K.o()` -> 0 |
| external executioner | forked watchdog: `ptrace` register corruption, and a 30-heartbeat completion deadline -> **SIGKILL** | `setprop debug.di.wdtest loop` |
| in-process executioner | `0x311fc` / `0x330c8` destructive stores -> SIGSEGV | native fault handler retires the faulting thread |
| secret gating | `K.g()` blocks on unlock material only published after a clean sweep | call the runtime's own publish routine; genuine `K.g()` then works |

### 1. `debug.di.wdtest` — the load-bearing finding

The watchdog child reads this property at `0x31b54` with **no guard** — no `ro.debuggable`,
no build variant, no UID check — and on `loop` calls `_exit(0)` before entering its message
loop. The check at `0x31b7c`–`0x31b94` is not conditional on the spawn flag, so *every*
child exits, first and respawned.

The respawn monitor cannot escalate: its failure counter resets on every **successful**
respawn (`mov w24, w25`, `w25=0`, `0x32f94`), and `0x31640` returns success whenever
`fork`/`socketpair` work — which they do; the child just leaves afterwards. Hence the
churning second PID in the trace above: it re-forks forever and never fires.

This matters because it is the **only** way to reach the kill from inside the process.
`adversarial/README.md` states the design intent exactly:

> *"the real executioner is a separate forked watchdog process — its code cannot be hooked
> from inside the app (post-`fork` copy-on-write), it re-forks if killed, and it crashes the
> app from the outside via `ptrace`"*

All true, and all bypassed — the child is never hooked, killed, or raced. It is asked to
leave. What it takes with it is the **uncatchable** half of enforcement: SIGKILL cannot be
caught, and the `ptrace` kill originates in another process. Setting one property downgrades
enforcement to an in-process fault, which by definition an in-process attacker can handle.

Measured, with the LSPosed hook held constant:

| `debug.di.wdtest` | outcome |
|---|---|
| unset | killed at 61s, **signal 9 (SIGKILL)**, no tombstone — completion deadline |
| `loop` | killed at 10s, **signal 11 (SIGSEGV)** at `libdicore+0x312f0` — in-process, catchable |
| `loop` + native handler | **survives** |

Privilege required: `adb shell`. `debug.*` is settable by the shell user on a stock Pixel —
below the floor of every attack in this suite, all of which need root plus a framework.

### 2. Retiring the executioner thread

`0x311fc` and `0x330c8` are wild-address stores inside flattened loops, so returning from a
handler (or stepping PC past the fault) just re-faults next iteration — as
`zygisk-survive-crash` notes. Instead the handler checks the fault PC against libdicore's
executable range and, on a match, parks that thread forever. The executioner never finishes;
everything else keeps running. Faults elsewhere are restored to `SIG_DFL` and re-raised, so
unrelated crashes are not masked.

```
armed: libdicore RX=[0x71b440a000,0x71b44c8170)
parked executioner thread: sig=11 pc=libdicore+0x312f0 addr=0x28 [parked=1]
```

One thread, once. Note the range is found with `dl_iterate_phdr`, not `/proc/self/maps` —
libdicore is mapped straight out of `base.apk`, so the maps view never contains the soname.

### 3. Opening the gate instead of reimplementing it

With the sweep skipped, `K.g()` blocks in `0x66378` waiting on unlock material that
`0x65b24` publishes only after a clean sweep, so the UI sits on `"🔒 …"` forever.

The module does **not** reimplement the key derivation. It calls the runtime's own publish
routine and lets the genuine native `K.g()` derive the key itself. `0x64790` is just:

```c
FUN_00165b24();                          // publish 32-byte unlock material + signal waiters
FUN_00165014();                          // arm the epoch observation
pthread_once(&once, FUN_001647b8);       // start the periodic re-sweep thread
```

We call only the first — so the gate opens, while no epoch is armed and no periodic
re-sweep thread is ever started:

```
calling publish-unlock at libdicore+0x65b24
unlock material published; native K.g() can now return the real key
```

No key schedule, no domain strings and no ciphertext live in the module. The address is a
single documented offset resolved against the load bias from `dl_iterate_phdr`, and the
handlers are armed *before* the call so a fault inside it is contained rather than fatal.

This is strictly stronger than deriving the key statically: it survives any change to the
key schedule, and it works for every gated value — `Hydra.secret` and `Hydra.asset` alike —
because the runtime does its own work.

**That the gate can be opened this way is the finding.** The unlock material is not a
secret the runtime holds back; it is a flag it sets after deciding it is happy. Anything
already inside the process can set it. And independently of this module, the key is
derivable with no device at all: `DiBaker.gatedDexKey` is `sha256` over two compiled-in
domain strings and a seed that ships in cleartext in the generated `Hydra.java`, so the key
can be reproduced from the APK without running anything. The sweep gate controls *when the
runtime hands over the key*, not whether an attacker can have it. (Reproduced locally to
confirm; the script is deliberately not included here.)

## Layout

```
full-bypass/
  module.prop, service.sh        Magisk module — sets debug.di.wdtest=loop at boot
  lsp/                           LSPosed module — K.o() hook + loader for the native half
  native/fullbypass.cpp          fault handler + unlock-material publish; ships in the APK
```

The native half rides in the LSPosed APK rather than a Zygisk slot: on this rig Magisk 30.7
never mapped a plain `zygisk/<abi>.so` module into the app (verified absent from
`/proc/<pid>/maps`), while Vector's injection works. Note Magisk *does* require both ABI
slots to exist — a missing `armeabi-v7a.so` aborts loading with
`openat 'zygisk/armeabi-v7a.so': No such file or directory`.

## Build + run

```bash
# Magisk half
adb push di-rt-full-bypass.zip /data/local/tmp/
adb shell su -c 'magisk --install-module /data/local/tmp/di-rt-full-bypass.zip'
adb reboot

# LSPosed half
NDK=<ndk-r27+> ./lsp/build.sh          # builds native + APK, signs it
adb install -r lsp/build/full-signed.apk
adb shell su -c '/data/adb/lspd/cli modules enable redteam.full.bypass'
adb shell su -c '/data/adb/lspd/cli scope set redteam.full.bypass com.example.hydrasample/0'

adb shell am start -n com.example.hydrasample/.MainActivity
sleep 240 && adb shell pidof com.example.hydrasample && echo "SURVIVED"
```

To revert: remove the module in Magisk Manager (or `rm -rf
/data/adb/modules/di_rt_full_bypass`), disable the LSPosed module, `resetprop --delete
debug.di.wdtest`, reboot.

## Suggested fixes

1. **Gate the `debug.di.wdtest` read** on a compile-time debug flag or the app's own
   `FLAG_DEBUGGABLE`, so it is inert in release builds. As shipped it is a device-wide
   disarm switch reachable with `adb shell`, and on a clean device it should also kill a
   *genuine* app once the watchdog goes missing — an availability bug as well as a bypass.
2. **Treat "child exited without ever completing a heartbeat" as a respawn failure**, so an
   immediately-exiting child cannot be recycled indefinitely.
3. **Stop treating the sweep as a confidentiality boundary.** Key material derivable from
   shipped constants cannot be protected by deciding when to hand it over. If the secret
   must survive a compromised device, release it from a server or bind it to hardware
   attestation, so failing the checks means the key does not exist locally. The in-process
   detectors are worth keeping as cost and telemetry — not as the thing standing between an
   attacker and the plaintext.


## Appendix — isolating the watchdog kill from the in-process kill

The crash signature identifies the executioner unambiguously, so the property's effect is
attributable even on a rooted device where detection trips regardless. Genuine app, no
LSPosed module, n=3 per arm:

| | control (property unset) | `debug.di.wdtest=loop` |
|---|---|---|
| time to death | 0.69 / 0.80 / 0.66 s | 2.32 / 2.32 / 2.28 s |
| signal | **7 (SIGBUS)** | **11 (SIGSEGV)** |
| faulting `pc` | `0x469`, `0xd81`, `0xc01` — *differs every run* | `0x3323c` — *identical every run* |
| `sp` | `0x460`, `0xd80`, `0xc00` | a real stack address |
| backtrace | `#00 pc <unknown>` | `#00 pc 0x3323c libdicore.so` |
| executioner | external watchdog, `PTRACE_SETREGSET` (`0x323dc`) | in-process destructive store |

The control's tiny, per-run-varying `pc`/`lr`/`sp` are the register image written by
`0x323dc` — mixed from time, PID and a stack address, then masked. With the property set
that signature disappears entirely and the process instead faults at `0x3323c`:

```asm
33230: ldr x24, [sp, #0x28]
33234: ldr x25, [sp, #0x10]
33238: mov x26, x10
3323c: str x25, [x24]        ; <-- SIGSEGV here, every run
```

`0x3323c` is inside `0x330c8`–`0x3380c`, the timed-death coordinator's in-process fallback.
The ~1.6 s delta is its documented "wait ~1.5 s for the child, then fall back" window: it
wrote `X` to the watchdog socket and nobody was listening.

Note this also means the property is an **availability bug** in its own right. On a clean,
unrooted device with no tamper present, setting it should still kill a genuine
hydra-protected app once the coordinator's window expires — the watchdog is simply absent.
That makes it a device-wide disarm/DoS switch against any hydra-protected app, not only the
sample. (Not measured here: this test device is rooted, so detection trips anyway.)

> Red-team, research only. Scoped to `com.example.hydrasample`; the hooks are inert for any
> other package. The property is hydra-specific and not a general-purpose evasion primitive.
