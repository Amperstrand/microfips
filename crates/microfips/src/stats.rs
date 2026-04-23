use core::sync::atomic::AtomicU32;

pub static PANIC_LINE: AtomicU32 = AtomicU32::new(0);
#[used]
pub static _PANIC_LINE_KEEP: &AtomicU32 = &PANIC_LINE;

#[used]
pub static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_USB_ERR: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_STATE: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_RECV_PKT: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_DATA_RX: AtomicU32 = AtomicU32::new(0);
#[used]
pub static STAT_DATA_TX: AtomicU32 = AtomicU32::new(0);
