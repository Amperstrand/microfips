MEMORY
{
    /* Instruction RAM — same as esp-hal default */
    IRAM : ORIGIN = 0x403DC000, LENGTH = 328K

    /* Data RAM — reduced by 2K to give more room to dram2_seg for WiFi blobs */
    DRAM : ORIGIN = 0x3FC80000, LENGTH = 328K

    /* dram2_seg extended for WiFi/Bluetooth precompiled blobs */
    dram2_seg ( RW ) : ORIGIN = ORIGIN(DRAM) + LENGTH(DRAM), LENGTH = 0x3FCE0000 - (ORIGIN(DRAM) + LENGTH(DRAM))

    /* External flash */
    IROM : ORIGIN =   0x42000000 + 0x20, LENGTH = 0x400000 - 0x20
    /* Data ROM */
    DROM : ORIGIN = 0x3C000000 + 0x20, LENGTH = 0x400000 - 0x20

    /* RTC fast memory (executable). Persists over deep sleep. */
    RTC_FAST : ORIGIN = 0x50000000, LENGTH = 0x2000
}
