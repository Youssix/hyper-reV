#pragma once
#include <cstdint>
#include <intrin.h>

namespace serial
{
    constexpr std::uint16_t COM1 = 0x3F8;

    // Initialize 16550 UART: 115200 baud, 8N1, FIFO enabled (boot-time)
    inline void init()
    {
        __outbyte(COM1 + 1, 0x00);  // Disable all interrupts
        __outbyte(COM1 + 3, 0x80);  // Enable DLAB (set baud rate divisor)
        __outbyte(COM1 + 0, 0x01);  // Divisor low byte: 115200 baud (divisor = 1)
        __outbyte(COM1 + 1, 0x00);  // Divisor high byte
        __outbyte(COM1 + 3, 0x03);  // 8 data bits, no parity, 1 stop bit (8N1)
        __outbyte(COM1 + 2, 0xC7);  // Enable FIFO, clear TX/RX, 14-byte threshold
        __outbyte(COM1 + 4, 0x03);  // RTS + DTR on (no IRQ)
    }

    // Aggressive re-init from VMX root — reclaims COM1 after Windows serial.sys
    // may have changed baud rate, FIFO, MCR, or enabled interrupts.
    // Double FCR write: first reset FIFOs, then set threshold.
    inline void reinit()
    {
        __outbyte(COM1 + 4, 0x00);  // Kill MCR first (drop RTS/DTR — break serial.sys grip)
        __outbyte(COM1 + 1, 0x00);  // Disable all interrupts
        __outbyte(COM1 + 3, 0x80);  // DLAB on
        __outbyte(COM1 + 0, 0x01);  // 115200 baud
        __outbyte(COM1 + 1, 0x00);  // Divisor high = 0
        __outbyte(COM1 + 3, 0x03);  // 8N1, DLAB off
        __outbyte(COM1 + 2, 0x07);  // Reset + enable FIFO (clear TX/RX queues)
        __outbyte(COM1 + 2, 0xC7);  // 14-byte threshold
        __outbyte(COM1 + 4, 0x03);  // RTS + DTR on, no IRQ
    }

    // Wait for Transmitter Holding Register Empty (LSR bit 5)
    inline void wait_tx_ready()
    {
        while ((__inbyte(COM1 + 5) & 0x20) == 0) { }
    }

    inline void put_char(const char c)
    {
        wait_tx_ready();
        __outbyte(COM1, static_cast<std::uint8_t>(c));
    }

    inline void print(const char* str)
    {
        while (*str) put_char(*str++);
    }

    inline void print_hex(std::uint64_t val)
    {
        const char hex[] = "0123456789ABCDEF";
        print("0x");
        for (int i = 60; i >= 0; i -= 4)
            put_char(hex[(val >> i) & 0xF]);
    }

    inline void println(const char* str)
    {
        print(str);
        put_char('\r');
        put_char('\n');
    }

    inline void print_byte_hex(std::uint8_t val)
    {
        const char hex[] = "0123456789ABCDEF";
        put_char(hex[(val >> 4) & 0xF]);
        put_char(hex[val & 0xF]);
    }

    inline void print_dec(std::uint64_t val)
    {
        if (val == 0) { put_char('0'); return; }
        char buf[20];
        int i = 0;
        while (val > 0 && i < 20) { buf[i++] = '0' + static_cast<char>(val % 10); val /= 10; }
        for (int j = i - 1; j >= 0; j--) put_char(buf[j]);
    }
}
