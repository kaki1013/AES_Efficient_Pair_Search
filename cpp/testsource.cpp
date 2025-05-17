#include <iostream>
#include <unordered_map>
#include <random>
#include <cstdint>
#include <cstdio>
#include <immintrin.h>

#define TEST_NUM 100
#define OUT_DIAG_NUM 8

#if OUT_DIAG_NUM == 4
    #define SELECTED_OU_IND ou_ind4
#elif OUT_DIAG_NUM == 8
    #define SELECTED_OU_IND ou_ind8
#else
    #error "지원되지 않는 OUT_DIAG_NUM 값입니다!"
#endif

extern "C" {
    #include "aes_tdc.h"
}

using namespace std;

void count_unordered_map(uint64_t *dat_tab, uint64_t *found_pairs2) {
    unordered_map<uint64_t, uint32_t> freqMap;
    for (uint64_t i = 0; i < num_dat; ++i) {
        uint64_t value = dat_tab[i];
        ++freqMap[value];
    }

    found_pairs2[0] = 0;
    for (const auto& [value, count] : freqMap) {
        found_pairs2[0] += static_cast<uint64_t>(count) * (count - 1) / 2;
    }
}

void get_time(uint8_t mk[16], uint8_t state[16], int32_t round, double * cpu_time_used1, double * cpu_time_used2) {
	uint64_t found_pairs1, found_pairs2;
	uint64_t *dat_tab;
	dat_tab = (uint64_t *)malloc(sizeof(uint64_t)*(num_dat));

	aes_encryption(mk, state, round, dat_tab);

    clock_t start, end;
	// ================================ test1 : hash table ================================
	start = clock();

	count_hash(dat_tab, &found_pairs1);

    end = clock();
	cpu_time_used1[0] += ((double)(end - start)) / CLOCKS_PER_SEC;

	if (found_pairs1 % 8) printf("Not multiple-of-8\n");
	printf("value1 = %llu\n", found_pairs1);

    // ================================ test2 : unordered map ================================
	start = clock();

	count_unordered_map(dat_tab, &found_pairs2);
 
    end = clock();
	cpu_time_used2[0] += ((double)(end - start)) / CLOCKS_PER_SEC;

	if (found_pairs2 % 8) printf("Not multiple-of-8\n");
	printf("value2 = %llu\n", found_pairs2);

	free(dat_tab);
}

int main() {
    int in_ind[4] = { 0, 5, 10, 15 };
	int ou_ind4[4] = { 0, 7, 10, 13 };
	int ou_ind8[8] = { 0, 1, 4, 7, 10, 11, 13, 14 };
	uint8_t mk[16], st[16];
	int i, j;

	double cpu_time_used1 = 0, cpu_time_used2 = 0;

	// file
	FILE *fp = fopen("output.txt", "w");
    if (fp == NULL) {
        perror("파일 열기 실패");
        return 1;
    }

	// experiment
	for (j = 0; j < TEST_NUM; j++)
	{
		if ((j) && (j % 10 == 0))
		{
			printf("\n");
			printf("Running Time(Hash Table): %f sec\n", cpu_time_used1);
			printf("Running Time(Unordered Map): %f sec\n", cpu_time_used2);
			printf("\n");
		}
		
		#ifdef _WIN64
		_rdrand64_step((unsigned long long*)(mk));
		_rdrand64_step((unsigned long long*)(mk + 8));
		_rdrand64_step((unsigned long long*)(st));
		_rdrand64_step((unsigned long long*)(st + 8));
#else
		_rdrand32_step((unsigned int*)(mk));
		_rdrand32_step((unsigned int*)(mk + 4));
		_rdrand32_step((unsigned int*)(mk + 8));
		_rdrand32_step((unsigned int*)(mk + 12));
		_rdrand32_step((unsigned int*)(st));
		_rdrand32_step((unsigned int*)(st + 4));
		_rdrand32_step((unsigned int*)(st + 8));
		_rdrand32_step((unsigned int*)(st + 12));
#endif // !_WIN32

		printf("Test %d..\n", j);
		fprintf(fp, "Test %d..\n", j);

		fprintf(fp, "MK : ");
		for (i = 0; i < 16; i++) fprintf(fp, "%02X ", mk[i]);
		fprintf(fp, "\n");

		fprintf(fp, "ST : ");
		for (i = 0; i < 16; i++) fprintf(fp, "%02X ", st[i]);
		fprintf(fp, "\n");

		SETTING_TDC_INFO(4, in_ind, OUT_DIAG_NUM, SELECTED_OU_IND);

        get_time(mk, st, 5, &cpu_time_used1, &cpu_time_used2);

		fprintf(fp, "Running Time(Hash Table): %f sec\n", cpu_time_used1);
		fprintf(fp, "Running Time(Unordered Map): %f sec\n", cpu_time_used2);
		fprintf(fp, "\n");

		fflush(fp);
	}

	printf("\nFinal Result\n");
	printf("Running Time(Hash Table): %f sec\n", cpu_time_used1);
	printf("Running Time(Unordered Map): %f sec\n", cpu_time_used2);

	fclose(fp);

    return 0;
}