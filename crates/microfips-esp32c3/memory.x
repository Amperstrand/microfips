MEMORY
{
    ICACHE : ORIGIN = 0x4037C000,  LENGTH = 0x4000
    /* Instruction RAM */
    IRAM : ORIGIN = 0x4037C000 + 0x4000, LENGTH = 313K - 0x4000
    /* Data RAM */
    DRAM : ORIGIN = 0x3FC80000, LENGTH = 311K

    /* dram2_seg extended to 0x3FCE0000 for WiFi/Bluetooth precompiled blobs */
    dram2_seg ( RW )       : ORIGIN = ORIGIN(DRAM) + LENGTH(DRAM), LENGTH = 0x3FCE0000 - (ORIGIN(DRAM) + LENGTH(DRAM))

    /* External flash */
    IROM : ORIGIN =   0x42000000 + 0x20, LENGTH = 0x400000 - 0x20
    /* Data ROM */
    DROM : ORIGIN = 0x3C000000 + 0x20, LENGTH = 0x400000 - 0x20

    /* RTC fast memory (executable). Persists over deep sleep. */
    RTC_FAST : ORIGIN = 0x50000000, LENGTH = 0x2000
}
