#[macro_export]
macro_rules! panic_blink {
    () => {
        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            loop {
                unsafe { $crate::gpio_helpers::gpio2_set() };
                for _ in 0..$crate::config::PANIC_BLINK_CYCLES {
                    core::hint::spin_loop();
                }
                unsafe { $crate::gpio_helpers::gpio2_clear() };
                for _ in 0..$crate::config::PANIC_BLINK_CYCLES {
                    core::hint::spin_loop();
                }
            }
        }
    };
}

#[macro_export]
macro_rules! panic_blink_print {
    () => {
        #[panic_handler]
        fn panic(info: &core::panic::PanicInfo) -> ! {
            esp_println::println!("PANIC: {}", info);
            loop {
                unsafe { $crate::gpio_helpers::gpio2_set() };
                for _ in 0..$crate::config::PANIC_BLINK_CYCLES {
                    core::hint::spin_loop();
                }
                unsafe { $crate::gpio_helpers::gpio2_clear() };
                for _ in 0..$crate::config::PANIC_BLINK_CYCLES {
                    core::hint::spin_loop();
                }
            }
        }
    };
}
