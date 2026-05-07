use embassy_stm32::rcc::*;
use embassy_stm32::Config;

#[cfg(feature = "display")]
pub const SYSCLK_HZ: u32 = 168_000_000;

pub fn configure_clocks(config: &mut Config) {
    #[cfg(feature = "display")]
    {
        config.rcc.hse = Some(Hse {
            freq: embassy_stm32::time::mhz(8),
            mode: HseMode::Oscillator,
        });
        config.rcc.pll_src = PllSource::HSE;
    }

    #[cfg(not(feature = "display"))]
    {
        config.rcc.pll_src = PllSource::HSI;
    }

    #[cfg(feature = "display")]
    let pll_mul = PllMul::MUL336;
    #[cfg(not(feature = "display"))]
    let pll_mul = PllMul::MUL168;

    config.rcc.pll = Some(Pll {
        prediv: PllPreDiv::DIV8,
        mul: pll_mul,
        divp: Some(PllPDiv::DIV2),
        divq: Some(PllQDiv::DIV7),
        divr: None,
    });

    #[cfg(feature = "display")]
    {
        config.rcc.pllsai = Some(Pll {
            prediv: PllPreDiv::DIV8,
            mul: PllMul::MUL384,
            divp: None,
            divq: None,
            divr: Some(PllRDiv::DIV7),
        });
    }

    config.rcc.sys = Sysclk::PLL1_P;
    config.rcc.ahb_pre = AHBPrescaler::DIV1;
    config.rcc.apb1_pre = APBPrescaler::DIV4;
    config.rcc.apb2_pre = APBPrescaler::DIV2;
    config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
}

pub const USB_SERIAL: &str = "stm32f469i-disc";
