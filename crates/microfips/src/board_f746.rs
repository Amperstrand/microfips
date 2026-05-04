use embassy_stm32::rcc::*;
use embassy_stm32::Config;

pub fn configure_clocks(config: &mut Config) {
    // HSI 16 MHz → PLL: /8 *216 /2 = 216 MHz sysclk, /9 = 48 MHz USB
    config.rcc.pll_src = PllSource::HSI;
    config.rcc.pll = Some(Pll {
        prediv: PllPreDiv::DIV8,
        mul: PllMul::MUL216,
        divp: Some(PllPDiv::DIV2),
        divq: Some(PllQDiv::DIV9),
        divr: None,
    });
    config.rcc.sys = Sysclk::PLL1_P;
    config.rcc.ahb_pre = AHBPrescaler::DIV1;
    config.rcc.apb1_pre = APBPrescaler::DIV4;
    config.rcc.apb2_pre = APBPrescaler::DIV2;
    config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
}

pub const USB_SERIAL: &str = "stm32f746g-disco";
