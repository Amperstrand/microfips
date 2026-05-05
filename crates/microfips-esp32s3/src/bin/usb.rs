#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::panic::PanicInfo;
use microfips_esp_transport::config::PANIC_BLINK_CYCLES;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    esp_println::println!("PANIC: {}", info);
    // SAFETY: GPIO::PTR is a fixed memory-mapped address (ESP32-S3 TRM §4.2).
    // The panic handler has exclusive access — interrupts are disabled and no
    // other code runs during panic.
    let gpio = unsafe { &*esp_hal::peripherals::GPIO::PTR };
    loop {
        gpio.out_w1ts()
            // SAFETY: Writing a raw bit value to the GPIO W1TS (write-1-to-set) register.
            // bits() is the only way to set the field value — svd2rust generates no safe setter.
            // The value (1 << 2) only sets GPIO2, which is the onboard LED.
            .write(|w| unsafe { w.out_w1ts().bits(1 << 2) });
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
        gpio.out_w1tc()
            // SAFETY: Writing a raw bit value to the GPIO W1TC (write-1-to-clear) register.
            // bits() is the only way to set the field value — svd2rust generates no safe setter.
            // The value (1 << 2) only clears GPIO2, which is the onboard LED.
            .write(|w| unsafe { w.out_w1tc().bits(1 << 2) });
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
    }
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    microfips_esp32s3::run::init_heap();
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let sw_int =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    microfips_esp32s3::run::run_usb_node(
        peripherals.GPIO2,
        peripherals.USB_DEVICE,
        peripherals.RNG,
        peripherals.ADC1,
    )
    .await
}
