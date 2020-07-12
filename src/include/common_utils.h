#ifndef _COMMON_UTILS_H
#define _COMMON_UTILS_H

namespace gf2_8_math {

	const uint16_t AESPOLY = 0x011b;

	// Functions
	uint16_t ff_mult (uint16_t op1, uint16_t op2);
	int ff_ord (uint16_t a);
	void ff_div (uint16_t op1, uint16_t op2, uint16_t * q, uint16_t * r);
	uint16_t ff_extEGCD (uint16_t a ,  uint16_t b, uint16_t *x, uint16_t *y);
	uint16_t ff_mult_inv( uint16_t a);
	uint16_t lshc(uint16_t x, int shift);

}

namespace gf2_128_math {
	void xor_acc (uint8_t *dst, const uint8_t *src);
	uint8_t rsh (uint8_t *a);
	void mult_gmac (uint8_t *res, const uint8_t *a, const uint8_t *b);
}

uint8_t char2hex (char ch); 
void ascii2hex (uint8_t *buf,const char * ascii);
void ascii2hex (uint8_t *buf, std::string ascii_str);
void x_bytes (uint8_t *a, int size);

#endif
