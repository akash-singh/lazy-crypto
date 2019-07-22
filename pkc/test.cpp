#include "arith.h"
#include <ctime>

std::clock_t c0,c1;

#define TICK c0 = std::clock();
#define TOCK \
c1 = std::clock(); \
std::cout << __LINE__ <<" : CPU time used: " << long (1000.0 * (c1-c0) / CLOCKS_PER_SEC) << " ms\n";

#define RADIX 1024

void test_mod() {
	for(int i=64; i<= 3072; i=i*2){
		bigInt a(i/32),m(i/64);
		a.randInit(); m.randInit();
		std::cout << "Radix is " << i  << " bits " << std::endl;
		TICK
		a.mod(m);
		TOCK
	}
}

int main() {
	
		//test_mod();
		
		bigInt m(RADIX/32);
		do {
			m.randInit();
		} while(m.isEven());
		
		bigInt a(RADIX/32),b(RADIX/32);
		a.randInit();
		b.randInit();
		
		a.mod(m);
		b.mod(m);

		
		bigInt c = a.expmod(b,m,true);

		std::cout << "python -c \"print(pow(" << a << "," << b << "," << m << ") == " << c << ")\"" ;
}