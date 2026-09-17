#!/system/bin/sh
# Disarm the forked watchdog child. Unguarded read at libdicore.so 0x31b54:
# value "loop" makes every watchdog child _exit(0) before it arms, which removes
# BOTH external kills (ptrace register corruption, and the 30-heartbeat completion
# deadline SIGKILL) and leaves only in-process faults, which the zygisk half retires.
resetprop debug.di.wdtest loop
