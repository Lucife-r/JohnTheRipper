// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015.  

// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)    

#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+1] = ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+2] = ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+3] = ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+0] = ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+0] += ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+1] += ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+2] += ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+3] += ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    temp = S[i0+3];         \
    S[i0+3] = S[i0+2];      \
    S[i0+2] = S[i0+1];      \
    S[i0+1] = S[i0+0];      \
    S[i0+0] = temp;         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

#define H(i, random_number)  {                                                      \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number  = S[i3];              \
    }                                        \
}

int POMELO(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost);
