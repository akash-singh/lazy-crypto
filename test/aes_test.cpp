#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include "yaml-cpp/yaml.h"
#include <assert.h>

#include "aes_block_cipher.h"
#include "common_utils.h"

uint8_t hexval (char n) {
	uint8_t val;
	if(n >= 'A' && n <= 'Z')
		val = n - 'A' + 10;
	else if (n >= 'a' && n <= 'z')
		val = n - 'a'+ 10;
	else if(n >= '0' && n <= '9')
		val = n - '0';
	else {
		std::cout << "Invalid hex char" << std::endl;
		std::exit(1);
	}

	return val;
}

std::vector<uint8_t> str2vec(const char *str) {
	std::size_t len = strlen(str);
	std::vector<uint8_t> vec;
	vec.reserve(len/2);
	for(std::size_t i=0; i < len; i+=2) 
		vec.push_back((hexval(str[i]) << 4) | hexval(str[i+1]));

	return vec;
} 

void test_ecb (YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();

	aes_ecb cipher(keylen*8);
	cipher.init_keys(key.data());
	std::vector<uint8_t> temp(ptlen,0);
	cipher.encrypt(pt.data(),temp.data(),ptlen/16);
	assert(temp == ct);
	cipher.decrypt(temp.data(),ct.data(),ptlen/16);
	assert(temp == pt);

}
void test_cbc (YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> iv = str2vec(node["iv"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();

	aes_cbc cipher(keylen*8);
	cipher.init_keys(key.data());
	std::vector<uint8_t> temp(ptlen,0);
	cipher.encrypt(pt.data(),temp.data(),iv.data(),ptlen/16);
	assert(temp == ct);
	cipher.decrypt(temp.data(),ct.data(),iv.data(),ptlen/16);
	assert(temp == pt);
}
void test_ofb (YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> iv = str2vec(node["iv"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();

	aes_ofb cipher(keylen*8);
	cipher.init_keys(key.data());
	std::vector<uint8_t> temp(ptlen,0);
	cipher.encrypt(pt.data(),temp.data(),iv.data(),ptlen/16);
	assert(temp == ct);
	cipher.decrypt(temp.data(),ct.data(),iv.data(),ptlen/16);
	assert(temp == pt);
}
void test_cfb (YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> iv = str2vec(node["iv"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();

	aes_cfb cipher(keylen*8);
	cipher.init_keys(key.data());
	std::vector<uint8_t> temp(ptlen,0);
	cipher.encrypt(pt.data(),temp.data(),iv.data(),ptlen/16);
	assert(temp == ct);
	cipher.decrypt(temp.data(),ct.data(),iv.data(),ptlen/16);
	assert(temp == pt);
}
void test_ctr (YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> iv = str2vec(node["iv"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();

	aes_ctr cipher(keylen*8);
	cipher.init_keys(key.data());
	std::vector<uint8_t> temp(ptlen,0);
	cipher.encrypt(pt.data(),temp.data(),iv.data(),ptlen/16);
	assert(temp == ct);
	cipher.decrypt(temp.data(),ct.data(),iv.data(),ptlen/16);
	assert(temp == pt);
}
void test_gcm(YAML::Node node) {
	std::vector<uint8_t> ct = str2vec(node["ct"].as<std::string>().c_str());
	std::vector<uint8_t> pt = str2vec(node["pt"].as<std::string>().c_str());
	std::vector<uint8_t> aad = str2vec(node["aad"].as<std::string>().c_str());
	std::vector<uint8_t> tag = str2vec(node["tag"].as<std::string>().c_str());
	std::vector<uint8_t> iv = str2vec(node["iv"].as<std::string>().c_str());
	std::vector<uint8_t> key = str2vec(node["key"].as<std::string>().c_str());

	int keylen = key.size();
	int ptlen = pt.size();
	int aadlen = aad.size();
	aes_gcm cipher(keylen*8);
	cipher.init_keys(key.data());

	std::vector<uint8_t> temp_data(ptlen,0);
	std::vector<uint8_t> temp_tag(16,0);

	cipher.encryptandsign (
		pt.data(), aad.data(), iv.data(), 
		temp_data.data(), temp_tag.data(), aadlen, ptlen
	);

	assert(temp_data == ct);
	assert(temp_tag == tag);

	bool result = 	cipher.decryptandverify (
		temp_data.data(), aad.data(), iv.data(), 
		ct.data(), tag.data(), aadlen, ptlen
	);

	assert (result == true);
	assert(temp_data == pt);

}

int main (int argc, char * argv[]) {

	YAML::Node root = YAML::LoadFile(argv[1]);

	int test_count = 0;
	for(YAML::const_iterator it = root.begin(); it != root.end(); it++) {
		std::string mode = (*it)["Mode"].as<std::string>();
		std::cout << "Executing Test # " << test_count++ << std::endl;
		if (mode == "AES_ECB")
			test_ecb(*it);
		else if (mode == "AES_CBC")
			test_cbc(*it);
		else if (mode == "AES_CFB")
			test_cfb(*it);
		else if (mode == "AES_OFB")
			test_ofb(*it);
		else if (mode == "AES_GCM")
			test_gcm(*it);
		else if (mode == "AES_CTR")
			test_ctr(*it);
		else 
			std::cout << "Unknown Mode of operation\n";
	}

}