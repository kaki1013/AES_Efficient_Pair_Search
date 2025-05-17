#include "ciphertools.h"

#include <time.h>
#include <immintrin.h>

#define TEST_NUM 100
#define OUT_DIAG_NUM 4

#if OUT_DIAG_NUM == 4
    #define SELECTED_OU_IND ou_ind4
#elif OUT_DIAG_NUM == 8
    #define SELECTED_OU_IND ou_ind8
#else
    #error "지원되지 않는 OUT_DIAG_NUM 값입니다!"
#endif

int main(void)
{
	int in_ind[4] = { 0, 5, 10, 15 };
	int ou_ind4[4] = { 0, 7, 10, 13 };
	int ou_ind8[8] = { 0, 1, 4, 7, 10, 11, 13, 14 };
	uint8_t mk[16], st[16];
	int i, j;

	double cpu_time_used1 = 0, cpu_time_used2 = 0, cpu_time_used3 = 0;

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
			printf("Running Time(Array     ): %f sec\n", cpu_time_used1);
			printf("Running Time(Quick Sort): %f sec\n", cpu_time_used2);
			printf("Running Time(Merge Sort): %f sec\n", cpu_time_used3);
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

		AES128_128_TDC_CHECK_NUM_ONLY(mk, st, 5, &cpu_time_used1, &cpu_time_used2, &cpu_time_used3);

		fprintf(fp, "Running Time(Array     ): %f sec\n", cpu_time_used1);
		fprintf(fp, "Running Time(Quick Sort): %f sec\n", cpu_time_used2);
		fprintf(fp, "Running Time(Merge Sort): %f sec\n", cpu_time_used3);
		fprintf(fp, "\n");

		fflush(fp);
	}

	printf("\nFinal Result\n");
	printf("Running Time(Array     ): %f sec\n", cpu_time_used1);
	printf("Running Time(Quick Sort): %f sec\n", cpu_time_used2);
	printf("Running Time(Merge Sort): %f sec\n", cpu_time_used3);

	fclose(fp);

	return 0;
}
