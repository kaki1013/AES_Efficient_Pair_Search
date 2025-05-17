#ifndef _CIPHERTOOLS_H_
#define _CIPHERTOOLS_H_


#ifdef __cplusplus
extern "C" {
#endif


#ifndef NOCRYPT
#define NOCRYPT
#endif

#if defined _MSC_VER
	//Visual Studio
#ifdef _DEVELOPMENT
#define DEV_DEFINE __declspec(dllexport)
#else
#define DEV_DEFINE __declspec(dllimport)
#endif
#elif defined __GNUC__
	//GCC
#ifdef _DEVELOPMENT
#define DEV_DEFINE __attribute__ ((visibility("default")))
#else
	//nothing to define
#define DEV_DEFINE 
#endif
#endif

#if defined	__NO_INLINE__
#define DEV_INLINE //nothing
#else
#define DEV_INLINE inline
#endif

#include <stdint.h>
#include <stdio.h>

	//ciphers
	DEV_DEFINE int AES128_128_ENC	(uint8_t ct[16], uint8_t pt[16], uint8_t mk[16], int32_t round);
	DEV_DEFINE int AES128_128_DEC	(uint8_t pt[16], uint8_t ct[16], uint8_t mk[16], int32_t round);
	DEV_DEFINE int AES128_192_ENC	(uint8_t ct[16], uint8_t pt[16], uint8_t mk[24], int32_t round);
	DEV_DEFINE int AES128_192_DEC	(uint8_t pt[16], uint8_t ct[16], uint8_t mk[24], int32_t round);
	DEV_DEFINE int AES128_256_ENC	(uint8_t ct[16], uint8_t pt[16], uint8_t mk[32], int32_t round);
	DEV_DEFINE int AES128_256_DEC	(uint8_t pt[16], uint8_t ct[16], uint8_t mk[32], int32_t round);
	DEV_DEFINE int ARIA128_128_ENC	(uint8_t ct[16], uint8_t pt[16], uint8_t mk[16], int32_t round);
	DEV_DEFINE int HIGHT64_128_ENC	(uint8_t ct[ 8], uint8_t pt[ 8], uint8_t mk[16], int32_t round);
	DEV_DEFINE int SEED128_128_ENC	(uint8_t ct[16], uint8_t pt[16], uint8_t mk[16], int32_t round);
	DEV_DEFINE int PRESENT64_80_ENC	(uint8_t ct[ 8], uint8_t pt[ 8], uint8_t mk[10], int32_t round);
	DEV_DEFINE int GIFT64_128_ENC	(uint8_t ct[ 8], uint8_t pt[ 8], uint8_t mk[16], int32_t round);
	DEV_DEFINE int SPECK32_64_ENC	(uint8_t ct[ 4], uint8_t pt[ 4], uint8_t mk[ 8], int32_t round);
	DEV_DEFINE int DES64_64_ENC		(uint8_t ct[ 8], uint8_t pt[ 8], uint8_t mk[ 8], int32_t round);
	DEV_DEFINE int DES64_56_ENC		(uint8_t ct[ 8], uint8_t pt[ 8], uint8_t mk[ 7], int32_t round);

	//analysis
	DEV_DEFINE void SETTING_TDC_INFO(int num_a_s_in, int * in_a_ind, int num_p_s_ou, int * ou_a_ind);

	#define NUM_CIPHERS_INCLUDED 14

	DEV_DEFINE void CHECK_PERFORMANCE(void);

#ifdef __cplusplus
}
#endif /*extern "C"*/

#endif /*_CIPHERTOOLS_H_*/