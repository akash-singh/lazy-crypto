#include <iostream>
#include <cstring>
#include <iomanip>
#include <cstdint>

#include  "common_utils.h"

uint16_t gf2_8_math::ff_mult (uint16_t op1, uint16_t op2) {
	uint16_t temp = 0;
	while (op1 && op2){
		if (op2 & 1) {  
			temp ^= op1;			
		}
		op1 = (op1 & 0x80) ? (op1  << 1) ^ AESPOLY : op1 << 1;


		op2 >>= 1;
	}

	return temp ;
}

int gf2_8_math::ff_ord (uint16_t a) {
	int order = 0;
	while (a != 0) {
		order++;
		a >>= 1;
	}
	return order;
}

void gf2_8_math::ff_div (uint16_t op1, uint16_t op2, uint16_t * q, uint16_t * r) { 
	*q = 0;
	*r = op1;
	int	 incr_q = ff_ord(*r) - ff_ord(op2);
	while (incr_q >= 0)  {
		*q |= 1 << incr_q;
		*r ^= (op2 << incr_q);
		incr_q = ff_ord(*r) - ff_ord(op2);
	}
}


// Extended Euclidean Algorithm to calculate GCD and coffs x and y
// such that a.x + b.y = gcd
uint16_t gf2_8_math::ff_extEGCD (uint16_t a ,  uint16_t b, uint16_t *x, uint16_t *y) {
	uint16_t gcd;
	if(b==0) {
	
		// last iter - 1.gcd + 0.0 = gcd
		*x = 1;
		*y = 0;
		
		return a;
	} else {
		uint16_t x1, y1; // placeholder for next iter to return evaluated coffs
		uint16_t q,r;
		ff_div(a,b,&q,&r);
		
		gcd = ff_extEGCD(b,r,&x1,&y1);
		
		// Eval and return curr coffs from the next iteration's coff
		*x = y1;
		*y = x1 ^ ff_mult(q,y1);
		
		return gcd;
	}
		
}

// Modulo N inverse (a^-1 mod N) - Calculates modulo N inverse using Extened Euclidean Algorith
// xN + ya = 1
// ya = 1 mod N
// y = a^-1 mod N

uint16_t gf2_8_math::ff_mult_inv( uint16_t a) {
	uint16_t inverse, dummy;
	uint16_t gcd = ff_extEGCD(AESPOLY,a,&dummy, &inverse);
	if (gcd == 1) {
		return inverse;
	} else {
		return 0;
	}
}

uint16_t gf2_8_math::lshc(uint16_t x, int shift) {
	return ((uint16_t) ((x) << (shift)) | ((x) >> (8 - (shift))) );
}
void gf2_128_math::xor_acc (uint8_t *dst, const uint8_t *src) {
	for(int i=0;i<16;i++)
		dst[i] ^= src[i] ;
}

uint8_t gf2_128_math::rsh (uint8_t *a) {
	uint8_t carry = 0, newcarry = 0;
    for(int i=0;i<16;i++) {
		newcarry = a[i] & 0x1;
        a[i] = (a[i] >> 1) | (carry << 7);
        carry = newcarry;
	}
	
	return carry;
}

void gf2_128_math::mult_gmac (uint8_t *res, const uint8_t *a, const uint8_t *b) {
	uint8_t v[16];
	uint8_t z[16];

	std::memset(z,0,16);
	std::memcpy(v,b,16);

	for(int i=0;i<16;i++) {
		for(int j=7;j>=0;j--) {
			if (a[i] & (1 << j)) 
			gf2_128_math::xor_acc(z,v);
			if(v[15] & 0x1) {
				gf2_128_math::rsh(v);
				v[0] ^= 0xE1;	// XOR with Char Polynomial E1 || 0^120
			} else{
				gf2_128_math::rsh(v);
			}
		}
	}
	
	std::memcpy(res,z,16);
}

uint8_t char2hex (char ch) {
	uint8_t nibble = ch;
	if (nibble >= '0' && nibble <= '9')
		nibble -= '0';
	else if (nibble >= 'A' && nibble <= 'F')
		nibble = nibble - 'A' + 10;
	else if (nibble >= 'a' && nibble <= 'f')	
		nibble = nibble - 'a' + 10;
	
	return nibble;
}

void ascii2hex (uint8_t *buf, const char *ascii) {
	std::string ascii_str = ascii;
	int numbytes = 0;
	for(std::string::iterator i=ascii_str.begin();i<ascii_str.end();i++) {
		buf[numbytes] = char2hex(*i) << 4;
		i++;
		buf[numbytes] |= char2hex(*i);
		numbytes++;
	}
}
void ascii2hex (uint8_t *buf, std::string ascii_str) {

	int numbytes = 0;
	for(std::string::iterator i=ascii_str.begin();i<ascii_str.end();i++) {
		buf[numbytes] = char2hex(*i) << 4;
		i++;
		buf[numbytes] |= char2hex(*i);
		numbytes++;
	}
}

void x_bytes (uint8_t *a, int size) {
	
	for(int i=0;i<size;i++)
		std::cout << std::hex << std::setfill('0') << std::setw(2) << (short) a[i] << " ";
	std::cout << std::endl;
}
