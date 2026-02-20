
#include "qemu/osdep.h"
#include "exec/memory.h"
#include "qemu/mmap-alloc.h"
#include "sysemu/kvm.h"

/*
 * Memory Interception for Infinite Scale (V18 - Dirty Log Enabled)
 */

void wavevm_setup_memory_region(MemoryRegion *mr, uint64_t size, int fd) {
    /*
     * Compatibility mode for QEMU 5.2:
     * The RAM region is already initialized by machine creation; reinitializing
     * it with memory_region_init_ram_ptr() can corrupt internal state and crash.
     * Keep existing RAM mapping and let WaveVM hooks operate on that memory.
     */
    (void)mr;
    (void)size;
    (void)fd;
}
