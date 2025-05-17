#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <immintrin.h>
#include <stdlib.h>
#include <time.h>
#include "ciphertools.h"
#include <inttypes.h>	// for PRIu64

#define AES128_128_ROUND 10
#define AES128_192_ROUND 12
#define AES128_256_ROUND 14

#define TABLE_SIZE	(1ULL << 32)

static int num_active_sboxes_in = 0;
static int num_pasive_sboxes_ou = 0;
static uint64_t num_dat         = 0;
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

int comp_partial_ct(const void * first, const void * second)
{
	uint64_t first_val  = *((uint64_t *)first);
	uint64_t second_val = *((uint64_t *)second);

	if (first_val == second_val)
		return 0;
	else if (first_val > second_val)
		return 1;
	else
		return -1;
}

struct list
{
	uint64_t 	item;
	int 		count;
	struct list *link;
};

uint32_t hash_function(uint64_t value)
{
	uint32_t high = (uint32_t)(value >> 32);
	uint32_t low  = (uint32_t)(value & 0xFFFFFFFF);
	return (high ^ low) % TABLE_SIZE;
}

void hash_chain_add(uint64_t item, struct list *ht[], struct list *memory_pool, uint64_t dat_idx)
{
	uint32_t hash_value = hash_function(item);
	struct list *node_before = NULL, *node = ht[hash_value];
	for (; node; node_before = node, node = node->link) {
		if (node->item == item) {
			node->count++;
			return;
		}
	}

	struct list *ptr = &memory_pool[dat_idx];
	
	ptr->item = item;
	ptr->count = 1;
	ptr->link = NULL;
	if (node_before)
		node_before->link = ptr;
	else  // if first add
		ht[hash_value] = ptr;
}

void merge(uint64_t *arr, uint64_t left, uint64_t mid, uint64_t right) {
    uint64_t n1 = mid - left + 1;
    uint64_t n2 = right - mid;

    uint64_t *L = malloc(n1 * sizeof(uint64_t));
    uint64_t *R = malloc(n2 * sizeof(uint64_t));

    if (!L || !R) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // copy left & right
    for (uint64_t i = 0; i < n1; i++) {
        L[i] = arr[left + i];
    }
    for (uint64_t j = 0; j < n2; j++) {
        R[j] = arr[mid + 1 + j];
    }

    // merging
    uint64_t i = 0, j = 0, k = left;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k] = L[i];
            i++;
        } else {
            arr[k] = R[j];
            j++;
        }
        k++;
    }

    // copy others
    while (i < n1) {
        arr[k] = L[i];
        i++;
        k++;
    }
    while (j < n2) {
        arr[k] = R[j];
        j++;
        k++;
    }

    free(L);
    free(R);
}

void merge_sort(uint64_t *arr, uint64_t left, uint64_t right) {
    if (left < right) {
        uint64_t mid = left + (right - left) / 2;

        merge_sort(arr, left, mid);
        merge_sort(arr, mid + 1, right);

        merge(arr, left, mid, right);
    }
}

void AES128_128_TDC_CHECK_NUM_ONLY(uint8_t mk[16], uint8_t state[16], int32_t round, double * cpu_time_used1, double * cpu_time_used2, double * cpu_time_used3)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];
	uint64_t *dat_tab;
	uint64_t dat_idx;
	uint8_t  * active_val_ptr = (uint8_t  *)&dat_idx;
	uint64_t cnt = 0, found_pairs1, found_pairs2, found_pairs3;

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
	
	dat_tab = (uint64_t *)malloc(sizeof(uint64_t)*(num_dat));

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

	clock_t start, end;
	// ================================ test1 : array  ================================
	start = clock();

	// memory allocation & init : array
	uint64_t * array = calloc(num_dat, sizeof(uint64_t));
	if (array == NULL) {
		perror("array calloc failed");
		exit(1);
	}

	// count
	for (dat_idx = 0; dat_idx < num_dat; dat_idx++) {
		array[dat_tab[dat_idx]]++;
	}

	found_pairs1 = 0;
	cnt = 0;
	for (dat_idx = 0; dat_idx < num_dat; dat_idx++) {
		// calc count
		cnt = array[dat_idx];
		found_pairs1 += (cnt * (cnt - 1) / 2);
	}
	free(array);

	end = clock();
	cpu_time_used1[0] += ((double)(end - start)) / CLOCKS_PER_SEC;

	if (found_pairs1 % 8) printf("Not multiple-of-8\n");
	printf("value1 = %" PRIu64 "\n", found_pairs1);

	// ================================ test2 : quick sort ================================
	// before clock starts, copy dat_tab
	uint64_t *dat_tab_ = (uint64_t *)malloc(sizeof(uint64_t)*(num_dat));
	for (dat_idx = 0; dat_idx < num_dat; dat_idx++) dat_tab_[dat_idx] = dat_tab[dat_idx];

	start = clock();

	found_pairs2 = 0;
	cnt = 0;
	qsort(dat_tab, num_dat, sizeof(uint64_t), comp_partial_ct);

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (dat_tab[dat_idx - 1] == dat_tab[dat_idx])
		{
			cnt = cnt + 1;
			found_pairs2 = found_pairs2 + cnt;
		}
		else
			cnt = 0;
	}
	free(dat_tab);

	end = clock();
	cpu_time_used2[0] += ((double)(end - start)) / CLOCKS_PER_SEC;

	if (found_pairs2 % 8) printf("Not multiple-of-8\n");
	printf("value2 = %" PRIu64 "\n", found_pairs2);

	// ================================ test3 : merge sort ================================
	start = clock();

	found_pairs3 = 0;
	cnt = 0;
	merge_sort(dat_tab_, 0, num_dat-1);

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (dat_tab_[dat_idx - 1] == dat_tab_[dat_idx])
		{
			cnt = cnt + 1;
			found_pairs3 = found_pairs3 + cnt;
		}
		else
			cnt = 0;
	}
	free(dat_tab_);

	end = clock();
	cpu_time_used3[0] += ((double)(end - start)) / CLOCKS_PER_SEC;

	if (found_pairs3 % 8) printf("Not multiple-of-8\n");
	printf("value3 = %" PRIu64 "\n", found_pairs3);

}
