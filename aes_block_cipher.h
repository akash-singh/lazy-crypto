#ifndef _AES_BLOCK_CIPHER_H
#define AES_BLOCK_CIPHER_H

#define AES128 128
#define AES192 192
#define AES256 256

class aes_block_cipher {
	
	private:	
		/* Variables */
		
		uint8_t 	fwd_sbox[256];
		uint8_t		bwd_sbox[256];
			
		int 		key_sz;	
		int 		num_key_words = 0;
		int 		num_key_exp_steps = 0;
		int 		key_exp_step_size = 0;
		
		uint32_t	key[8];
		uint32_t	key_sch[64];
		
		int 		num_rounds = 0;
		
		/* Internal Functions */
		
		// Initialization
		void 		generate_sbox();			
		int 		generate_key_schedule();
		
		// Helper functions
		void 		rows2cols(uint32_t rows[4], uint32_t cols[4]);
		void 		cols2rows(uint32_t cols[4], uint32_t rows[4]);
		
		// Enc/Dec sub-steps
		uint32_t 	byte_sub(uint32_t src, bool is_fwd);
		uint32_t 	mix_cols(uint32_t col, bool is_fwd);
		void 		aes_enc_block_op(uint32_t *block, uint32_t * round_key, bool is_last_block);
		
		void		aes_dec_block_op(uint32_t *block, uint32_t * round_key, bool is_last_block);
		
	public:
		aes_block_cipher (int key_sz);
		
		void init_keys(uint8_t *key_bytes);
		void encrypt_block (const uint8_t *pt, uint8_t *ct);
		void decrypt_block (uint8_t *pt, const uint8_t *ct);
};

class aes_ecb : public aes_block_cipher {
	
	public:
		aes_ecb (int key_size);	
		void encrypt (const uint8_t *pt, uint8_t *ct, int num_blocks);
		void decrypt (uint8_t *pt, const uint8_t *ct, int num_blocks);

};

class aes_cbc : public aes_block_cipher {
	
	public:
		aes_cbc (int key_size);	
		void encrypt (const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks);
		void decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks);

};

class aes_cfb : public aes_block_cipher {
	
	public:
		aes_cfb (int key_size);	
		void encrypt (const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks);
		void decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks);

};

class aes_ofb : public aes_block_cipher {
	
	public:
		aes_ofb (int key_size);	
		void encrypt (const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks);
		void decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks);

};

class aes_ctr : public aes_block_cipher {
	
	public:
		aes_ctr (int key_size);	
		void encrypt (const uint8_t *pt, uint8_t *ct, const uint8_t *iv, int num_blocks);
		void decrypt (uint8_t *pt, const uint8_t *ct, const uint8_t *iv, int num_blocks);

};

class aes_gcm : public aes_block_cipher {
	
	public:
		aes_gcm (int key_size);	
		void incr_cntr(uint8_t *cntr);
		void encryptandsign   (const uint8_t *pt, const uint8_t *aad, const uint8_t *iv, uint8_t *ct, uint8_t *tag, int num_aad_blocks, int num_pt_blocks);
		bool decryptandverify (uint8_t *pt, const uint8_t *aad, const uint8_t *iv, const uint8_t *ct, const uint8_t *tag,  int num_aad_blocks, int num_pt_blocks);

};
#endif