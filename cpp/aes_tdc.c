#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <immintrin.h>
#include <stdlib.h>
#include <time.h>
#include "ciphertools.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>	// for PRIu64

#define AES128_128_ROUND 10
#define AES128_192_ROUND 12
#define AES128_256_ROUND 14

#define TABLE_SIZE	(1ULL << 32)

static int num_active_sboxes_in = 0;
static int num_pasive_sboxes_ou = 0;
uint64_t num_dat         = 0;
static int * in_active_indexes  = NULL;
static int * ou_pasive_indexes 	= NULL;

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

void SETTING_TDC_INFO(int num_a_s_in, int * in_a_ind, int num_p_s_ou, int * ou_a_ind)
{
	num_active_sboxes_in = num_a_s_in;
	num_pasive_sboxes_ou = num_p_s_ou;

	if (in_active_indexes != NULL)
	{
		free(in_active_indexes);
		in_active_indexes = NULL;
	}
	if (ou_pasive_indexes != NULL)
	{
		free(ou_pasive_indexes);
		ou_pasive_indexes = NULL;
	}

	in_active_indexes = (int *)malloc(sizeof(int) * num_a_s_in);
	ou_pasive_indexes = (int *)malloc(sizeof(int) * num_p_s_ou);

	memcpy(in_active_indexes, in_a_ind, sizeof(int) * num_a_s_in);
	memcpy(ou_pasive_indexes, ou_a_ind, sizeof(int) * num_p_s_ou);

	num_dat = (1ULL) << (num_a_s_in * 8);
}

struct my_list
{
	uint64_t 		item;
	int 			count;
	struct my_list 	*link;
};

void hash_chain_add(uint64_t item, struct my_list *ht[], struct my_list *memory_pool, uint64_t dat_idx)
{
	// hash function : left ^ right
	uint32_t hash_value = (uint32_t)((item >> 32) ^ (item & 0xFFFFFFFF));

	struct my_list *node_before = NULL, *node = ht[hash_value];
	for (; node; node_before = node, node = node->link) {
		if (node->item == item) {
			node->count++;
			return;
		}
	}

	struct my_list *ptr = &memory_pool[dat_idx];
	ptr->item = item;
	ptr->count = 1;
	ptr->link = NULL;

	if (node_before)
		node_before->link = ptr;
	else  // if first add
		ht[hash_value] = ptr;
}

void aes_encryption(uint8_t mk[16], uint8_t state[16], int32_t round, uint64_t *dat_tab) {
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];
	uint64_t dat_idx;
	uint8_t  * active_val_ptr = (uint8_t  *)&dat_idx;

	/*KeyExpansion()*/
	RoundKey[0] = _mm_loadu_si128((const __m128i*) mk);
	RoundKey[1] = AES_128_key_exp(RoundKey[0], 0x01);
	RoundKey[2] = AES_128_key_exp(RoundKey[1], 0x02);
	RoundKey[3] = AES_128_key_exp(RoundKey[2], 0x04);
	RoundKey[4] = AES_128_key_exp(RoundKey[3], 0x08);
	RoundKey[5] = AES_128_key_exp(RoundKey[4], 0x10);
	RoundKey[6] = AES_128_key_exp(RoundKey[5], 0x20);
	RoundKey[7] = AES_128_key_exp(RoundKey[6], 0x40);
	RoundKey[8] = AES_128_key_exp(RoundKey[7], 0x80);
	RoundKey[9] = AES_128_key_exp(RoundKey[8], 0x1B);
	RoundKey[10] = AES_128_key_exp(RoundKey[9], 0x36);

	for (dat_idx = 0; dat_idx < num_dat; dat_idx++)
	{
		int idx;
		__m128i tmp_state;
		uint8_t tmp_cp[16];
		uint8_t * dat_tab_byte_ptr = (uint8_t *)&dat_tab[dat_idx];

		//consider little-endian
		for (idx = 0; idx < num_active_sboxes_in; idx++)
		{
			state[in_active_indexes[idx]] = active_val_ptr[idx];
		}

		///////////////////////////////////////////////////////////////
		//Encryption
		tmp_state = _mm_loadu_si128((__m128i *) state);

		// Add the First round key to the state before starting the rounds.
		tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

		// There will be Nr rounds.
		// The first Nr-1 rounds are identical.
		// These Nr-1 rounds are executed in the loop below.
		for (round_idx = 1; round_idx < round; ++round_idx)
		{
			tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);
		}

		// The last round is given below.
		// The MixColumns function is not here in the last round.
		tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);
		///////////////////////////////////////////////////////////////
		_mm_storeu_si128((__m128i *) tmp_cp, tmp_state);

		dat_tab[dat_idx] = 0;
		for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
		{
			dat_tab_byte_ptr[idx] = tmp_cp[ou_pasive_indexes[idx]];
		}
	}
}

void count_hash(uint64_t *dat_tab, uint64_t *found_pairs1) {
		// memory allocation & init : hash table
		struct my_list **hash_table = (struct my_list **)calloc(TABLE_SIZE, sizeof(struct my_list *));
		if (hash_table == NULL) {
			perror("hash_table calloc failed");
			exit(1);
		}
	
		// memory allocation : memory pool
		struct my_list *memory_pool = (struct my_list *)malloc(sizeof(struct my_list) * num_dat);
		if (memory_pool == NULL) {
			perror("memory_pool malloc failed");
			exit(1);
		}
	
		// hash_chain_add
		for (uint64_t dat_idx = 0; dat_idx < num_dat; dat_idx++) {
			hash_chain_add(dat_tab[dat_idx], hash_table, memory_pool, dat_idx);
		}
	
		found_pairs1[0] = 0;
		uint64_t cnt = 0;
		for (uint64_t idx = 0; idx < TABLE_SIZE; idx++) {
			struct my_list *node = hash_table[idx];
			while (node != NULL) {
				// calc count
				cnt = node->count;
				found_pairs1[0] += (cnt * (cnt - 1) / 2);
	
				node = node->link;
			}
			hash_table[idx] = NULL;
		}
		
		free(hash_table);
		free(memory_pool);
}
