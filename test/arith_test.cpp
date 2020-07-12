#include "arith.h"
#include "yaml-cpp/yaml.h"
#include "common_utils.h"
#include <ctime>

std::clock_t c0,c1;

#define TICK c0 = std::clock();
#define TOCK \
c1 = std::clock(); \
std::cout << __FILE__ << ":" << __LINE__ <<" : CPU time used: " << long (1000.0 * (c1-c0) / CLOCKS_PER_SEC) << " ms\n";

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

std::vector<uint32_t> adapter(std::vector<uint8_t> in) {
	std::vector<uint32_t> out;

	for(int i=in.size()-1; i >= 0; i-=4) {
		uint32_t val = in[i];
		val |= in[i-1] << 8;
		val |= in[i-2] << 16;
		val |= in[i-3] << 24;
		
		out.push_back(val);
	}
	return out;
}

void test_expmodm (YAML::Node node) {
	int radix = node["radix"].as<int>();
	std::vector<uint32_t> X = adapter(str2vec(node["x"].as<std::string>().c_str()));
	std::vector<uint32_t> A = adapter(str2vec(node["a"].as<std::string>().c_str()));
	std::vector<uint32_t> M = adapter(str2vec(node["m"].as<std::string>().c_str()));
	std::vector<uint32_t> Y = adapter(str2vec(node["y"].as<std::string>().c_str()));

	bigInt x(X.data(), radix/32);
	bigInt a(A.data(), radix/32);
	bigInt m(M.data(), radix/32);
	bigInt y(Y.data(), radix/32);

	std::cout << "Testing Exp mod M" << std::endl;
	TICK
	bigInt calc_y = x.expmod(a,m,true);
	TOCK
	assert(calc_y == y);
}
int main (int argc, char * argv[]) {

	YAML::Node root = YAML::LoadFile(argv[1]);
	
	int test_count = 0;
	for(YAML::const_iterator it = root.begin(); it != root.end(); it++) {		
		test_expmodm(*it);
	}

}