use embassy_stm32::Config;

/// Returns a clock config from BSP presets (display) or hand-rolled HSI-only (non-display).
///
/// BSP presets are hardware-verified on STM32F469I-Discovery (issue BSP#28).
/// Non-display uses HSI-only 168 MHz for maximum compatibility (no external oscillator needed).
pub fn clock_config() -> Config {
    #[cfg(feature = "display")]
    {
        embassy_stm32f469i_disco::config_168()
    }

    #[cfg(not(feature = "display"))]
    {
        use embassy_stm32::rcc::*;

        let mut config = embassy_stm32::Config::default();
        config.rcc.pll_src = PllSource::HSI;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV8,
            mul: PllMul::MUL168,
            divp: Some(PllPDiv::DIV2),
            divq: Some(PllQDiv::DIV7),
            divr: None,
        });
        config.rcc.sys = Sysclk::PLL1_P;
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
        config
    }
}

pub const USB_SERIAL: &str = "stm32f469i-disc";
