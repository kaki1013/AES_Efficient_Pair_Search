// aes_tdc.h
#ifndef AES_TDC_H
#define AES_TDC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t num_dat;

void SETTING_TDC_INFO(int num_a_s_in, int * in_a_ind, int num_p_s_ou, int * ou_a_ind);
void aes_encryption(uint8_t mk[16], uint8_t state[16], int32_t round, uint64_t *dat_tab);
void count_hash(uint64_t *dat_tab, uint64_t *found_pairs1);

#ifdef __cplusplus
}
#endif

#endif // AES_TDC_H
