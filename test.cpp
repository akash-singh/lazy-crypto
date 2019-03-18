#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <assert.h>

#include "aes_block_cipher.h"
#include "common_utils.h"

void test_gcm (	std::string	keystr,
				std::string ivstr,
				std::string ptstr,
				std::string ctstr,
				std::string aadstr,
				std::string tagstr
				) {

	uint8_t * gcm_key  = new uint8_t [keystr.size()/2]; 
	uint8_t * gcm_iv   = new uint8_t [ivstr.size()/2]; 
	uint8_t * gcm_pt   = new uint8_t [ptstr.size()/2]; 
	uint8_t * calc_pt  = new uint8_t [ptstr.size()/2]; 
	uint8_t * gcm_ct   = new uint8_t [ctstr.size()/2]; 
	uint8_t * calc_ct  = new uint8_t [ctstr.size()/2]; 
	uint8_t * gcm_aad  = new uint8_t [aadstr.size()/2];
	uint8_t * gcm_tag  = new uint8_t [128];
	uint8_t * calc_tag = new uint8_t [128];
	
	assert (ptstr.size() == ctstr.size());
	
	ascii2hex(gcm_key,keystr);
	ascii2hex(gcm_iv,ivstr);
	ascii2hex(gcm_pt,ptstr);
	ascii2hex(gcm_ct,ctstr);
	ascii2hex(gcm_aad,aadstr);
	ascii2hex(gcm_tag,tagstr);

	std::memset(calc_ct,0,ptstr.size()/2);
	std::memset(calc_pt,0,ptstr.size()/2);

	aes_gcm c1(keystr.size()/2*8);
	
	c1.init_keys(gcm_key);
	c1.encryptandsign(gcm_pt,gcm_aad,gcm_iv,calc_ct,calc_tag,aadstr.size()/2,ptstr.size()/2);
	
	assert (!std::memcmp(gcm_ct,calc_ct,ptstr.size()/2));
	assert (!std::memcmp(gcm_tag,calc_tag,tagstr.size()/2));

	
	bool res = c1.decryptandverify(calc_pt,gcm_aad,gcm_iv,gcm_ct,gcm_tag,aadstr.size()/2,ptstr.size()/2);

	assert (res==true);
	assert (!std::memcmp(gcm_pt,calc_pt,ptstr.size()/2));
	
	delete gcm_key;
	delete gcm_iv;
	delete gcm_pt;
	delete calc_pt;
	delete gcm_ct;
	delete calc_ct;
	delete gcm_aad;
	delete gcm_tag;
	delete calc_tag;

	
}
																
int main() {
	uint8_t key_128[16], key_192[192], key_256[256];
	ascii2hex(key_128,"2b7e151628aed2a6abf7158809cf4f3c");
	ascii2hex(key_192,"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	ascii2hex(key_256,"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	
	uint8_t iv[16];
	ascii2hex(iv,"000102030405060708090a0b0c0d0e0f");
	
	uint8_t pt[64], calc_pt[64], ct[64], calc_ct[64];
	ascii2hex(pt,"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	aes_ecb *ecb;
	
	ascii2hex(ct,"3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ecb = new aes_ecb (128);
	ecb->init_keys(key_128);
	ecb->encrypt(pt,calc_ct,4);
	ecb->decrypt(calc_pt,ct,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ecb;
	
	
	ascii2hex(ct,"bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ecb = new aes_ecb (192);
	ecb->init_keys(key_192);
	ecb->encrypt(pt,calc_ct,4);
	ecb->decrypt(calc_pt,ct,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ecb;
	
	ascii2hex(ct,"f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ecb = new aes_ecb (256);
	ecb->init_keys(key_256);
	ecb->encrypt(pt,calc_ct,4);
	ecb->decrypt(calc_pt,ct,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ecb;
	
	aes_cbc *cbc;
	
	ascii2hex(ct,"7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cbc = new aes_cbc (128);
	cbc->init_keys(key_128);
	cbc->encrypt(pt,calc_ct,iv,4);
	cbc->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cbc;
	
	ascii2hex(ct,"4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cbc = new aes_cbc (192);
	cbc->init_keys(key_192);
	cbc->encrypt(pt,calc_ct,iv,4);
	cbc->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cbc;

	ascii2hex(ct,"f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cbc = new aes_cbc (256);
	cbc->init_keys(key_256);
	cbc->encrypt(pt,calc_ct,iv,4);
	cbc->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cbc;
	
	aes_cfb *cfb;
	
	ascii2hex(ct,"3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cfb = new aes_cfb (128);
	cfb->init_keys(key_128);
	cfb->encrypt(pt,calc_ct,iv,4);
	cfb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cfb;
	
	ascii2hex(ct,"cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cfb = new aes_cfb (192);
	cfb->init_keys(key_192);
	cfb->encrypt(pt,calc_ct,iv,4);
	cfb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cfb;

	ascii2hex(ct,"dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	cfb = new aes_cfb (256);
	cfb->init_keys(key_256);
	cfb->encrypt(pt,calc_ct,iv,4);
	cfb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete cfb;
	
		aes_ofb *ofb;
	
	ascii2hex(ct,"3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ofb = new aes_ofb (128);
	ofb->init_keys(key_128);
	ofb->encrypt(pt,calc_ct,iv,4);
	ofb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ofb;
	
	ascii2hex(ct,"cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ofb = new aes_ofb (192);
	ofb->init_keys(key_192);
	ofb->encrypt(pt,calc_ct,iv,4);
	ofb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ofb;

	ascii2hex(ct,"dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ofb = new aes_ofb (256);
	ofb->init_keys(key_256);
	ofb->encrypt(pt,calc_ct,iv,4);
	ofb->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ofb;

	ascii2hex(iv,"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	
	aes_ctr *ctr;
	
	ascii2hex(ct,"874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ctr = new aes_ctr (128);
	ctr->init_keys(key_128);
	ctr->encrypt(pt,calc_ct,iv,4);
	ctr->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ctr;
	
	ascii2hex(ct,"1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ctr = new aes_ctr (192);
	ctr->init_keys(key_192);
	ctr->encrypt(pt,calc_ct,iv,4);
	ctr->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ctr;

	ascii2hex(ct,"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
	std::memset(calc_ct,0,64);
	std::memset(calc_pt,0,64);
	ctr = new aes_ctr (256);
	ctr->init_keys(key_256);
	ctr->encrypt(pt,calc_ct,iv,4);
	ctr->decrypt(calc_pt,ct,iv,4);
	assert(!std::memcmp(ct,calc_ct,64));
	assert(!std::memcmp(pt,calc_pt,64));
	delete ctr;
	

	std::string keystr = "9c0a76be7069251f9f960af2c4df42d4";
	std::string ivstr  = "d8d9897641ecd9e6ef250ac7";
	std::string ptstr  = "be65081bb605840e88c5612670338b253240f88bb9e10077b188a924bf056c268ca6586934486a53876e449664f8fb5b66bdba";
	std::string ctstr  = "07fd9fce64e0650b77c261f2a9ab35c59c05f1c162bc3ab86bd4ee7e2203e0f0229cd1392c98ae78286b1218789428707c3733";
	std::string aadstr = "8cef51d28c793eea1773b5d8f826ae62a5763ab1a40368d4abac76cf4aeffb3fce7d488a589ca741f7d415001050b00bf783bc8f3d46d5d3ab6fdbd7247980896fd24019b3e1973cc49a5282c1e733f9edec9951951444ccf935";
	std::string tagstr = "414d0d29a2f8e98838f5c15ee715450e";
	
	test_gcm(keystr,ivstr,ptstr,ctstr,aadstr,tagstr);
	
	keystr = "2c23d0684c07ed2f8ba7ddffd5044b5e";
	ivstr  = "5faf18ebb36026aed4cfaec4";
	ptstr  = "d94073da254eacf055a4c2252b26c54b44061b3e9786f346817ff22d1627e31c1a9191bbd9c4e4e3d1903c4ca05f5afd0dfd17";
	aadstr = "b23beecffe38a8e22449da953a926b4c372b666d5f6e9d9793b60782fa4fc950aed9814aade36c5ad67107fb18b65d5bc385bb3ce60f6f098d9b75e885b897f2e0e620d53f402afab33ffab792d8c0feffffd9e026bbdd002d72";
	ctstr  = "de59a633ccb2cbe55b3d362fa9e85c0c1b3841e025893051b9d8da34855bee2ff269a0df04bdaf0c6e273e81fc9cf72527d7b3";
	tagstr = "5e29b1493ef9fa7cdafa3f11092619bd";
	test_gcm(keystr,ivstr,ptstr,ctstr,aadstr,tagstr);
	
	std::cout << "All tests passed\n" ;
}