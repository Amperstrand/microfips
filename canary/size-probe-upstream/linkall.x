/* Same -T for both probes: generic FLASH/RAM regions; the image never runs, */
/* lld only needs valid memory to place sections. Emitted by build.rs with an */
/* absolute path so it is independent of the invoking directory. */
ENTRY(_probe_entry)
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2048K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 512K
}
SECTIONS
{
  .text : { KEEP(*(.literal._probe_entry)) KEEP(*(.text._probe_entry)) *(.literal .text .literal.* .text.*) *(.rodata .rodata.*) } > FLASH
  .data : { *(.data .data.*) *(.sdata .sdata.*) *(.got .got.*) } > RAM
  .bss  : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) } > RAM
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
