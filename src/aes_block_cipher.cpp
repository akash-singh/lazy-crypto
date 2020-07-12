#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "aes_block_cipher.h"
#include "common_utils.h"


/****************************************************************
	Basic AES Block Cipher
****************************************************************/

// Public Functions

// Constructor - Takes key size as argument, valid values are - 128,193 and 256
aes_block_cipher::aes_block_cipher (int key_sz) {
	switch (key_sz) {
		case 128:
			key_exp_step_size = 4;
			num_key_exp_steps = 10;
			num_key_words = 4;
			num_rounds = 10;
			break;
		case 192:
			key_exp_step_size = 6;
			num_key_exp_steps = 9;
			num_key_words = 6;
			num_rounds = 12;
			break;
		case 256:
			key_exp_step_size = 8;
			num_key_exp_steps = 7;
			num_key_words = 8;
			num_rounds = 14;
			break;
		default:
			std::cout << "Error: Illegal key size" << std::endl;
			std::exit(-1);
			break;
	}
	
	this->key_sz = key_sz;
	
	generate_sbox();
}

// Initialize Cipher with given keys and calculate
// key schedule for all rounds
// Expects key in the following format
// B0 B1 B2 ...  , Bn - nth byte having bits in order b7,b6,b5 ... b0
// In terms of AES blocks, this is how exanded key schedule looks like
// 		B0 B4 B8  B12 ...
// 		B1 B5 B9  B13 ...
// 		B2 B6 B10 B14 ...
// 		B3 B7 B11 B15 ...
void aes_block_cipher::init_keys (uint8_t *key_bytes) {
	for(int i=0;i<num_key_words;i++) {
		key[i] = 0;
		for(int j=0;j<4;j++) {
			key[i] |= key_bytes[i*4+j] << (24-j*8);
		}
	}
	generate_key_schedule();		 
}

// Encryption/Decryption Operations 128b data block
// PT/CT is expected in the form of array of 16 uint8_t values. Layout -
// B0 B1 B2 ... B16 , bn - nth Byte having bits in order b7,b6,b5 ... b0
// Layouy of AES 4x4 block -
// 		B0 B4 B8  B12
// 		B1 B5 B9  B13
// 		B2 B6 B10 B14
// 		B3 B7 B11 B15
void aes_block_cipher::encrypt_block (const uint8_t *pt, uint8_t *ct) {
	uint32_t buf[4];
	
	for(int i=0;i<4;i++) {
		buf[i] = 0;
		for(int j=0;j<4;j++) {
			buf[i] |= pt[i*4+j] << (24-j*8);
		}
	}
	
	uint32_t *round_key = &key_sch[0];
	
	// Add round key to input
	for (int i=0;i<4;i++)
		buf[i] ^= round_key[i];
	
	for(int i=1;i<=num_rounds;i++) {
		round_key += 4;
		aes_enc_block_op(buf,round_key,(i==num_rounds));
	}					
	
	for(int i=0;i<4;i++) 
		for(int j=0;j<4;j++) 
			ct[i*4+j] = uint8_t (buf[i] >> (24-8*j) );
	
	
}

void aes_block_cipher::decrypt_block (uint8_t *pt, const uint8_t *ct) {

	uint32_t buf[4];

	uint32_t *round_key = key_sch+(num_rounds*4);
			
	for(int i=0;i<4;i++) {
		buf[i] = 0;
		for(int j=0;j<4;j++) {
			buf[i] |= ct[i*4+j] << (24-j*8);
		}
	}
		
	for(int i=num_rounds;i>=1;i--) {
		aes_dec_block_op(buf,round_key,(i==num_rounds));
		round_key -= 4;
	}		
	
	// Add round key to input
	for (int i=0;i<4;i++)
		buf[i] ^= round_key[i];
	
	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			pt[i*4+j] = uint8_t (buf[i] >> (24-8*j) );
			
}

// Private Helper functions

// Generates forward and reverse sbox tables by calculating multiplicative inverse in GF(2^8)
void aes_block_cipher::generate_sbox() {
	for(int i=0;i<256;i++) {
		uint8_t inv = gf2_8_math::ff_mult_inv(i);
		fwd_sbox[i] = inv ^ gf2_8_math::lshc(inv,1) ^ gf2_8_math::lshc(inv,2) ^ gf2_8_math::lshc(inv,3) ^ gf2_8_math::lshc(inv,4) ^ 0x63;
		bwd_sbox[fwd_sbox[i]] = i;
	}	
}

// Performs AES key expansion
int aes_block_cipher::generate_key_schedule() {
	
	const uint32_t rcon[] = {0x0,0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000}; 
	
	for (int i=0;i<key_exp_step_size;i++)
		key_sch[i] = key[i];
	
	for (int step=1; step<=num_key_exp_steps; step++){
	
		int ind_w0 = step * key_exp_step_size;
		int ind_last_w0 = (step-1) * key_exp_step_size;
		
		// calculate g(last_round's last word) -- circular shift left followed by bytesub
		uint32_t lrlw = key_sch[ind_w0 - 1];
		lrlw = (lrlw << 8) | (lrlw >> 24);
		
		lrlw = byte_sub(lrlw,true);					
		lrlw ^= rcon[step];	// XOR with Round constant
					
		key_sch[ind_w0] = key_sch[ind_last_w0] ^ lrlw; 
		
		for (int i=1;i<key_exp_step_size;i++){
			uint32_t temp = key_sch[ind_w0 + i-1];
			
			if (key_sz==256 && i==4)
				temp = byte_sub(temp,true);
			
			key_sch[ind_w0+i] = key_sch[ind_last_w0+i] ^ temp;
		}
	}
	return 0;
}

void aes_block_cipher::aes_enc_block_op (uint32_t *block, uint32_t * round_key, bool is_last_block) {
	
	 uint32_t temp[4];
	 for(int i=0;i<4;i++)
	 	temp[i] = block[i];
	
	// Byte sub
	for(int i=0;i<4;i++)
		temp[i] = byte_sub(temp[i],true);
		
	// Shift Rows
	uint32_t rows[4];
	cols2rows(temp,rows);
	for(int i=1;i<4;i++)
		rows[i] = (rows[i] << (i*8)) | rows[i] >> (32-i*8);
	rows2cols(rows,temp);
	
	// Mix cols
	if (is_last_block == false) {
		for(int i=0;i<4;i++)
			temp[i] = mix_cols(temp[i],true);
	}
	
	// Add Round key
	for (int i=0;i<4;i++)
		temp[i] ^= round_key[i];
	
	// Copy final output back
	for (int i=0;i<4;i++)
		block[i] = temp[i];	
}

// 1 round of AES encryption/decryption
void aes_block_cipher::aes_dec_block_op (uint32_t *block, uint32_t * round_key, bool is_last_block) {
	
	 uint32_t temp[4];
	 
	 for(int i=0;i<4;i++)
	 	temp[i] = block[i];

	// Add Round key
	for (int i=0;i<4;i++)
		temp[i] ^= round_key[i];

	// Inv Mix cols
	if (is_last_block == false) {
		for(int i=0;i<4;i++)
			temp[i] = mix_cols(temp[i],false);
	}
	
	// Inv Shift Rows
	uint32_t rows[4];
	cols2rows(temp,rows);
	for(int i=1;i<4;i++)
		rows[i] = (rows[i] >> (i*8)) | rows[i] << (32-i*8);
	rows2cols(rows,temp);

	// Inv Byte sub
	for(int i=0;i<4;i++)
		temp[i] = byte_sub(temp[i],false);

	// Copy final output back
	for (int i=0;i<4;i++)
		block[i] = temp[i];	

}


// Sub-operation within an AES block

// Byte sub -- Expects and returns data a 32 bit word
// b3,b2,b1,b0 (wn or 1 column of AES block)
uint32_t aes_block_cipher::byte_sub (uint32_t src, bool is_fwd) {
	uint32_t dest = src;
	uint8_t *byte_ptr = (uint8_t *) &dest;
		
	for(int i=0;i<4;i++)
		*(byte_ptr+i) = is_fwd ? fwd_sbox[*(byte_ptr+i)] : bwd_sbox[*(byte_ptr+i)];
	
	return dest;
}

// Interchanging b/w row packed <--> col packed formats
// Used for mix columns operation
void aes_block_cipher::rows2cols	 (uint32_t rows[4], uint32_t cols[4]) {
	
	uint8_t mat[4][4];
	
	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			mat[i][j] = uint8_t (rows[i] >> (24-j*8) );   
	
	for(int i=0;i<4;i++)
		cols[i] = uint32_t ((mat[0][i] << 24) | (mat[1][i] << 16) | (mat[2][i] << 8) | (mat[3][i]) );

}

void aes_block_cipher::cols2rows (uint32_t cols[4], uint32_t rows[4]) {

	uint8_t mat[4][4];
	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			mat[i][j] = uint8_t (cols[j] >> (24-i*8) );   
	
	for (int i=0;i<4;i++)
		rows[i] = uint32_t ((mat[i][0] << 24) | (mat[i][1] << 16) | (mat[i][2] << 8) | (mat[i][3]) );
	
}

// AES mix column operation
uint32_t aes_block_cipher::mix_cols (uint32_t col, bool is_fwd) {
	uint8_t col_vec[4];
	for(int i=0;i<4;i++)
		col_vec[i] = (uint8_t) (col >> (24-i*8));
	
	
	uint8_t fwd_coff[4][4] = {{0x02,0x03,0x01,0x01},
						 	  {0x01,0x02,0x03,0x01},
						 	  {0x01,0x01,0x02,0x03},
					 		  {0x03,0x01,0x01,0x02}};
							  
	uint8_t rev_coff[4][4] = {{0x0e,0x0b,0x0d,0x09},
						 	  {0x09,0x0e,0x0b,0x0d},
						 	  {0x0d,0x09,0x0e,0x0b},
					 		  {0x0b,0x0d,0x09,0x0e}};
	
	uint32_t res = 0;
	
	for(int i=0;i<4;i++) {
		uint8_t acc = 0;
		for(int j=0;j<4;j++) {
			uint8_t product;
			if (is_fwd)
				product = gf2_8_math::ff_mult(fwd_coff[i][j], col_vec[j]);
			else
				product = gf2_8_math::ff_mult(rev_coff[i][j], col_vec[j]);
			
			acc ^= product;
		}
		res |= uint32_t (acc << (24-i*8));
	}
	
	return res;
}
			
/****************************************************************
	AES for bigger blocks - Electronic Code Book (ECB) Mode
****************************************************************/

aes_ecb::aes_ecb(int key_size) : aes_block_cipher(key_size) {
}

void aes_ecb::encrypt (const uint8_t *pt, uint8_t *ct, int num_blocks) {
	for(int i=0;i<num_blocks;i++)
		encrypt_block(pt+(i*16), ct+(i*16));
}

void aes_ecb::decrypt (uint8_t *pt, const uint8_t *ct, int num_blocks) {
	
	for(int i=0;i<num_blocks;i++)
		decrypt_block(pt+(i*16), ct+(i*16));
}


/****************************************************************
	AES for bigger blocks - Cipher Block Chain (CBC) Mode
****************************************************************/

aes_cbc::aes_cbc(int key_size) : aes_block_cipher(key_size) {
}

void aes_cbc::encrypt(const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	for(int i=0;i<16;i++)
		ct[i] = pt[i] ^ iv[i];
	
	encrypt_block(ct,ct);
	
	for(int i=1;i<num_blocks;i++) {
		for (int j=0;j<16;j++) {
			ct[i*16+j] = pt[i*16+j] ^ ct[(i-1)*16+j];
		}
		encrypt_block(ct+(i*16),ct+(i*16));
		
	}
		
}

void aes_cbc::decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks) {
	decrypt_block(pt,ct);
	
	for(int i=0;i<16;i++)
		pt[i] ^= iv[i];
	
	for (int i=1;i<num_blocks;i++) {
		decrypt_block(pt+i*16,ct+i*16);	
		for(int j=0;j<16;j++)
			pt[i*16+j] ^= ct[(i-1)*16+j];
	}
}

/****************************************************************
	AES for bigger blocks - Cipher Feed Back (CFB) Mode
****************************************************************/

aes_cfb::aes_cfb(int key_size) : aes_block_cipher(key_size) {
}

void aes_cfb::encrypt(const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	encrypt_block(iv,ct);
	
	for(int i=0;i<16;i++)
		ct[i] ^= pt[i];
	
	for(int i=1;i<num_blocks;i++) {
		encrypt_block(ct+(i-1)*16,ct+i*16);
		
		for (int j=0;j<16;j++) 
			ct[i*16+j] ^= pt[i*16+j];
	}	
}

void aes_cfb::decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	encrypt_block(iv,pt);
	
	for(int i=0;i<16;i++)
		pt[i] ^= ct[i];
	
	for(int i=1;i<num_blocks;i++) {
		encrypt_block(ct+(i-1)*16,pt+i*16);
		
		for (int j=0;j<16;j++) 
			pt[i*16+j] ^= ct[i*16+j];
	}	
}

/****************************************************************
	AES for bigger blocks - Output Feed Back (OFB) Mode
****************************************************************/

aes_ofb::aes_ofb(int key_size) : aes_block_cipher(key_size) {
}

void aes_ofb::encrypt(const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	uint8_t output[16];
	encrypt_block(iv,output);
	
	for(int i=0;i<16;i++)
		ct[i] = output[i] ^ pt[i];
	
	for(int i=1;i<num_blocks;i++) {
		encrypt_block(output,output);
		
		for (int j=0;j<16;j++) 
			ct[i*16+j] = pt[i*16+j] ^ output[j];
	}	
}

void aes_ofb::decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	uint8_t output[16];
	encrypt_block(iv,output);
	
	for(int i=0;i<16;i++)
		pt[i] = output[i] ^ ct[i];
	
	for(int i=1;i<num_blocks;i++) {
		encrypt_block(output,output);
		
		for (int j=0;j<16;j++) 
			pt[i*16+j] = ct[i*16+j] ^ output[j];
	}	
}

/****************************************************************
	AES for bigger blocks - Counter (CTR) Mode
****************************************************************/
aes_ctr::aes_ctr(int key_size) : aes_block_cipher(key_size) {
}

void aes_ctr::encrypt(const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	uint8_t cntr[16], cntr_enc[16];
	
	for(int i=0;i<16;i++)
		cntr[i] = iv[i];
	
	for(int i=0;i<num_blocks;i++) {
		encrypt_block(cntr,cntr_enc);
		
		for (int j=0;j<16;j++) 
			ct[i*16+j] = pt[i*16+j] ^ cntr_enc[j];
		
		uint16_t temp;
		for(int k=15;k>=0;k--) {
			temp = cntr[k] + 1;
			cntr[k] = uint8_t (temp);
			if(temp >> 8 == 0)
				break;
		}
	}	
}

void aes_ctr::decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks) {
	
	uint8_t cntr[16], cntr_enc[16];
	
	for(int i=0;i<16;i++)
		cntr[i] = iv[i];
	
	for(int i=0;i<num_blocks;i++) {
		encrypt_block(cntr,cntr_enc);
		
		for (int j=0;j<16;j++) 
			pt[i*16+j] = ct[i*16+j] ^ cntr_enc[j];
		
		// increment cntr
		uint16_t temp;
		for(int k=15;k>=0;k--) {
			temp = cntr[k] + 1;
			cntr[k] = uint8_t (temp);
			if(temp >> 8 == 0)
				break;
		}
		
	}	
	
}

/****************************************************************
	AES for bigger blocks - Galois Counter Mode (GCM)
****************************************************************/

aes_gcm::aes_gcm(int key_sz) :  aes_block_cipher ( key_sz) {
}

void aes_gcm::incr_cntr(uint8_t *cntr) {
	uint16_t temp;
	for(int k=15;k>=0;k--) {
		temp = cntr[k] + 1;
		cntr[k] = uint8_t (temp);
		if(temp >> 8 == 0)
			break;
	}	
}

void aes_gcm::encryptandsign (	const uint8_t *pt, 
								const uint8_t *aad, 
								const uint8_t *iv, 
								uint8_t *ct, 
								uint8_t *tag, 
								int num_aad_bytes, 
								int num_pt_bytes
							) 
{

	uint8_t cntr[16],cntr_enc[16];
	
	std::memcpy(cntr,iv,12);
	std::memset(cntr+12,0,4);
	
	cntr[15] = 0x1;
	uint8_t cntr0_enc[16];
	encrypt_block(cntr,cntr0_enc);
	
	//uint8_t tag[16];
	std::memset(tag,0,16);
	
	uint8_t h[16];
	std::memset(h,0,16);
	encrypt_block(h,h);
	
	int num_full_aad_blocks   = num_aad_bytes/16;
	int num_partial_aad_bytes = num_aad_bytes%16;
	
	int num_full_pt_blocks 		= num_pt_bytes/16;
	int num_partial_pt_bytes	= num_pt_bytes%16;
	
	for(int i=0; i<num_full_aad_blocks; i++) {
		uint8_t newtag[16];
		gf2_128_math::xor_acc(tag,aad+i*16);
		gf2_128_math::mult_gmac(newtag, tag ,h);
		std::memcpy(tag,newtag,16);
	}

	if (num_partial_aad_bytes > 0) {
		uint8_t temp[16];
		std::memcpy(temp,aad+(num_full_aad_blocks*16),num_partial_aad_bytes);
		std::memset(temp+num_partial_aad_bytes,0,16-num_partial_aad_bytes);
		gf2_128_math::xor_acc(tag,temp);
		gf2_128_math::mult_gmac(temp,tag,h);
		std::memcpy(tag,temp,16);
	}

	for(int i=0;i<num_full_pt_blocks;i++) {
		
		// increment cntr
		incr_cntr(cntr);
		encrypt_block(cntr,cntr_enc);
	
		for (int j=0;j<16;j++) 
			ct[i*16+j] = pt[i*16+j] ^ cntr_enc[j];
	
		gf2_128_math::xor_acc(tag,ct+i*16);
		
		gf2_128_math::mult_gmac(tag,tag,h);
		
	}

	if (num_partial_pt_bytes > 0) {
		uint8_t partial_ct_block[16];
		
		incr_cntr(cntr);
		encrypt_block(cntr,cntr_enc);
		
		for (int j=0;j<num_partial_pt_bytes;j++) 
			partial_ct_block[j] = pt[num_full_pt_blocks*16+j] ^ cntr_enc[j];
		
		std::memcpy(ct+num_full_pt_blocks*16,partial_ct_block,num_partial_pt_bytes);
		std::memset(partial_ct_block+num_partial_pt_bytes,0,16-num_partial_pt_bytes);

		
		gf2_128_math::xor_acc(tag,partial_ct_block);
		gf2_128_math::mult_gmac(tag,tag,h);

	}

	uint8_t len[16];
	std::memset(len,0,16);
	
	// len(a) || len(c)
	unsigned int len_ct =  num_pt_bytes * 8;
	unsigned int len_aad = num_aad_bytes * 8;
	len[15] = uint8_t ( len_ct & 0xFF);
	len[14] = uint8_t ((len_ct & 0xFFFF) >> 8);
	len[13] = uint8_t ((len_ct & 0xFFFFFF) >> 16);
	len[12] = uint8_t (len_ct >> 24);
	
	len[7] = uint8_t ( len_aad & 0xFF);
	len[6] = uint8_t ((len_aad & 0xFFFF) >> 8);
	len[5] = uint8_t ((len_aad & 0xFFFFFF) >> 16);
	len[4] = uint8_t (len_aad >> 24);
	
	
	gf2_128_math::xor_acc(tag, len);
	gf2_128_math::mult_gmac(tag,tag,h);
	
	gf2_128_math::xor_acc(tag,cntr0_enc);
	
}

bool aes_gcm::decryptandverify (	uint8_t *pt, 
									const uint8_t *aad, 
									const uint8_t *iv, 
									const uint8_t *ct, 
									const uint8_t *tag, 
									int num_aad_bytes, 
									int num_pt_bytes
							) 
{
	uint8_t cntr[16],cntr_enc[16],calc_tag[16];
	
	int num_full_aad_blocks 	= num_aad_bytes/16;
	int num_partial_aad_bytes	= num_aad_bytes%16;
	
	int num_full_pt_blocks		= num_pt_bytes/16;
	int num_partial_pt_bytes	= num_pt_bytes%16;
	
	std::memcpy(cntr,iv,12);
	std::memset(cntr+12,0,4);
	
	cntr[15] = 0x1;
	uint8_t cntr0_enc[16];
	encrypt_block(cntr,cntr0_enc);
	
	// Verify
	std::memset(calc_tag,0,16);
	
	uint8_t h[16];
	std::memset(h,0,16);
	encrypt_block(h,h);
	
	for(int i=0; i<num_full_aad_blocks; i++) {
		uint8_t newtag[16];
		gf2_128_math::xor_acc(calc_tag,aad+i*16);
		gf2_128_math::mult_gmac(newtag, calc_tag ,h);
		std::memcpy(calc_tag,newtag,16);
	}

	if (num_partial_aad_bytes > 0) {
		uint8_t temp[16];
		std::memcpy(temp,aad+(num_full_aad_blocks*16),num_partial_aad_bytes);
		std::memset(temp+num_partial_aad_bytes,0,16-num_partial_aad_bytes);
		gf2_128_math::xor_acc(calc_tag,temp);
		gf2_128_math::mult_gmac(calc_tag,calc_tag,h);
	}
	
	for(int i=0;i<num_full_pt_blocks;i++) {
	
		gf2_128_math::xor_acc(calc_tag,ct+i*16);
		gf2_128_math::mult_gmac(calc_tag,calc_tag,h);
		
	}
	
	if (num_partial_pt_bytes > 0) {
		uint8_t partial_ct_block[16];
		
		std::memcpy(partial_ct_block,ct+num_full_pt_blocks*16,num_partial_pt_bytes);
		std::memset(partial_ct_block+num_partial_pt_bytes,0,16-num_partial_pt_bytes);
		
		gf2_128_math::xor_acc(calc_tag,partial_ct_block);
		gf2_128_math::mult_gmac(calc_tag,calc_tag,h);

	}
	
	uint8_t len[16];
	std::memset(len,0,16);
	
	// len(a) || len(c)
	unsigned int len_ct =  num_pt_bytes * 8;
	unsigned int len_aad = num_aad_bytes * 8;
	len[15] = uint8_t ( len_ct & 0xFF);
	len[14] = uint8_t ((len_ct & 0xFFFF) >> 8);
	len[13] = uint8_t ((len_ct & 0xFFFFFF) >> 16);
	len[12] = uint8_t (len_ct >> 24);
	
	len[7] = uint8_t ( len_aad & 0xFF);
	len[6] = uint8_t ((len_aad & 0xFFFF) >> 8);
	len[5] = uint8_t ((len_aad & 0xFFFFFF) >> 16);
	len[4] = uint8_t (len_aad >> 24);
	
	gf2_128_math::xor_acc(calc_tag, len);
	gf2_128_math::mult_gmac(calc_tag,calc_tag,h);
	
	gf2_128_math::xor_acc(calc_tag,cntr0_enc);
								
	bool tagv_res =  std::memcmp(calc_tag,tag,16) == 0;
	
	uint8_t l_pt [num_pt_bytes];
	
	for(int i=0;i<num_full_pt_blocks;i++) {
		
		incr_cntr(cntr);
		encrypt_block(cntr,cntr_enc);
	
		for (int j=0;j<16;j++) 
			l_pt[i*16+j] = ct[i*16+j] ^ cntr_enc[j];

	}
		
	if (num_partial_pt_bytes > 0) {
		
		incr_cntr(cntr);
		encrypt_block(cntr,cntr_enc);
		
		uint8_t temp_pt[16];
		
		for (int j=0;j<num_partial_pt_bytes;j++) 
			temp_pt[j] = ct[num_full_pt_blocks*16+j] ^ cntr_enc[j];
		
		
		std::memcpy(l_pt+num_full_pt_blocks*16,temp_pt,num_partial_pt_bytes);
		
	}
	
	if (tagv_res == true)
		std::memcpy(pt,l_pt,num_pt_bytes);
	else 
		std::memset(pt,0,num_pt_bytes);
	
	return tagv_res;
}
