// Ghidra-Rare: calling-convention probe for the SDCC (GBDK-2020) sm83 ABI; Apache-2.0 like the rest of the module.
#include <stdint.h>
#include <gb/gb.h>
uint8_t add8(uint8_t a, uint8_t b) { return a + b; }
uint16_t add16(uint16_t a, uint16_t b) { return a + b; }
uint8_t first_plus(uint8_t *p, uint8_t n) { return p[0] + n; }
uint16_t scale(uint8_t a, uint16_t b) { return b * a + 1; }
uint32_t mix(uint32_t a, uint8_t b) { return a + b; }
uint8_t many(uint8_t a, uint8_t b, uint8_t c, uint8_t d) { return a + b * c - d; }
void store(uint8_t *p, uint8_t v) { *p = v; }
uint8_t g;
void main(void) {
    g = add8(1, 2);
    g += (uint8_t)add16(300, 400);
    g += first_plus(&g, 3);
    g += (uint8_t)scale(g, 1000);
    g += (uint8_t)mix(70000UL, g);
    g += many(1, 2, 3, g);
    store(&g, 9);
    while (1) { wait_vbl_done(); }
}
