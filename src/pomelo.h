// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015.  

// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)    

#ifndef pomelo_h
#define pomelo_h

#include <stdio.h>
#include <inttypes.h>
#include "arch.h"

int POMELO(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost);

#ifdef __AVX2__
int POMELO_AVX2(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost);


#elif defined(SIMD_COEF_64)

int POMELO_SSE2(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost);

#endif

#endif
