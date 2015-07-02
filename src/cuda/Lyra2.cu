/**
 * A simple attack against Lyra2 Password Hashing Scheme (PHS).
 * This is a specific implementation, used only to start
 * evaluating GPU attacks. This implementation needs improvement
 * in specific GPU optimization technics.
 *
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on June,2015.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "Lyra2.h"
#include "Sponge.h"

extern "C" void multPasswordCUDA(unsigned char *K, int kLen, unsigned char *passwords, int pwdLen, unsigned char *salt, int saltLen, unsigned int t_cost, unsigned int m_cost, unsigned int nPARALLEL, unsigned int C_COLS, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize);


/**
 * Generates the passwords for Lyra2 attack.
 *
 * @param t_cost            Parameter to determine the processing time (T)
 * @param m_cost            Memory cost parameter (defines the number of rows of the memory matrix, R)
 * @param totalPasswords    Total number of passwords being tested
 * @param gridSize          GPU grid configuration
 * @param blockSize         GPU block configuration
 * @param printKeys         Defines if the resulting keys will be in the output
 */
__host__ void multPasswordCUDA(unsigned char *K, int kLen, unsigned char *passwords, int pwdLen, unsigned char *salt, int saltLen, unsigned int t_cost, unsigned int m_cost, unsigned int nPARALLEL, unsigned int N_COLS, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize) {
    //=================== Basic variables, with default values =======================//

    //==========================================================================/
    if (m_cost / nPARALLEL < 4) {
        printf("Number of rows too small\n");
        exit(0);
    }

    //Calls the interface to the GPU program
    gpuMult(K, kLen, passwords, pwdLen, salt, saltLen, t_cost, m_cost, nPARALLEL, N_COLS, totalPasswords, gridSize, blockSize);

    cudaDeviceReset();
}

int gpuMult(void *K, unsigned int kLen, unsigned char *passwords, unsigned int pwdlen, unsigned char *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nPARALLEL, unsigned int N_COLS, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize) {
    int result = 0;

    //============================= Basic variables ============================//
    int64_t i, j, k; //auxiliary iteration counter

    cudaError_t errorCUDA;
    uint64_t sizeSlice = nRows / nPARALLEL;
    //==========================================================================/

    //Checks kernel geometry configuration
    if ((gridSize * blockSize) != (totalPasswords * nPARALLEL)) {
        printf("Error in thread geometry: (gridSize * blockSize) != (totalPasswords * nPARALLEL).\n");
        return -1;
    }

    //========== Initializing the Memory Matrix and Keys =============//
    //Allocates the keys
    unsigned char *pKeys = (unsigned char *) malloc(totalPasswords * nPARALLEL * kLen * sizeof (unsigned char));
    if (pKeys == NULL) {
        return -1;
    }

    // GPU memory matrix alloc:
    // Memory matrix: nRows of N_COLS blocks, each block having BLOCK_LEN_INT64 64-bit words
    uint64_t *memMatrixGPU;
    errorCUDA = cudaMalloc((void**) &memMatrixGPU, totalPasswords * nRows * ROW_LEN_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the GPU keys
    unsigned char *pkeysGPU;
    errorCUDA = cudaMalloc((void**) &pkeysGPU, totalPasswords * nPARALLEL * kLen * sizeof (unsigned char));
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
    uint64_t *stateThreadGPU;
    errorCUDA = cudaMalloc((void**) &stateThreadGPU, totalPasswords * nPARALLEL * STATESIZE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // stateThreadGPU cleanup:
    cudaMemset(stateThreadGPU, 0, totalPasswords * nPARALLEL * STATESIZE_BYTES);
    if (cudaSuccess != cudaGetLastError()) {
        printf("CUDA memory setting error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(cudaGetLastError()));
        return -2;
    }

    //Allocates the State Index to be absorbed by each thread.
    uint64_t *stateIdxGPU;
    errorCUDA = cudaMalloc((void**) &stateIdxGPU, totalPasswords * nPARALLEL * BLOCK_LEN_BLAKE2_SAFE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Password in GPU.
    unsigned char *pwdGPU;
    errorCUDA = cudaMalloc((void**) &pwdGPU, totalPasswords * pwdlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the password to GPU.
    errorCUDA = cudaMemcpy(pwdGPU, passwords, totalPasswords * pwdlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Salt in GPU.
    unsigned char *saltGPU;
    errorCUDA = cudaMalloc((void**) &saltGPU, saltlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the salt to GPU.
    errorCUDA = cudaMemcpy(saltGPU, salt, saltlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    bootStrapGPU <<<gridSize, blockSize>>>(memMatrixGPU, pkeysGPU, kLen, pwdGPU, pwdlen, saltGPU, saltlen, timeCost, nRows, N_COLS, totalPasswords, nPARALLEL, N_COLS);

    // Needs to wait all threads:
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //============== Initializing the Sponge State =============/
    initState <<<gridSize, blockSize>>>(stateThreadGPU, totalPasswords, nPARALLEL);

    // Wait all threads to verify execution errors.
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //============= Absorbing the input data with the sponge ===============//
    absorbInput <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, stateIdxGPU, pwdGPU, pwdlen, saltlen, totalPasswords, nPARALLEL);

    // Wait all threads to verify execution errors.
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //================================ Setup and Wandering Phase =============================//
    //Initializes M[0]
    reducedSqueezeRow0 <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, totalPasswords, nPARALLEL, N_COLS); //The locally copied password is most likely overwritten here

    // Wait all threads to verify execution errors.
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Initializes M[1]
    reducedDuplexRow1and2 <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, totalPasswords, 0, 1, nPARALLEL, N_COLS);

    // Wait all threads to verify execution errors.
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Initializes M[2]
    reducedDuplexRow1and2 <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, totalPasswords, 1, 2, nPARALLEL, N_COLS);

    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }
if (nPARALLEL == 1)
    // Runs Setup and Wandering Phase
    setupPhaseWanderingGPU_P1 <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, sizeSlice, totalPasswords, timeCost, nPARALLEL, N_COLS);

if (nPARALLEL > 1)
    // Runs Setup and Wandering Phase
    setupPhaseWanderingGPU <<<gridSize, blockSize>>>(memMatrixGPU, stateThreadGPU, sizeSlice, totalPasswords, timeCost, nPARALLEL, N_COLS);

    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error after SetupWandering: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Squeezes the keys
    squeeze <<<gridSize, blockSize>>>(stateThreadGPU, pkeysGPU, kLen, totalPasswords, nPARALLEL);

    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Getting the keys back.
    errorCUDA = cudaMemcpy(pKeys, pkeysGPU, totalPasswords * nPARALLEL * kLen * sizeof (unsigned char), cudaMemcpyDeviceToHost);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }


if (nPARALLEL > 1)
{
    // XORs all Keys
    for (k = 0; k < totalPasswords; k++) {
        for (i = 1; i < nPARALLEL; i++) {
            for (j = 0; j < kLen; j++) {
                pKeys[k * kLen * nPARALLEL + j] ^= pKeys[k * kLen * nPARALLEL + i * kLen + j];
            }
        }
    }

    //Move the keys to proper place
    for (k = 1; k < totalPasswords; k++) {
        for (j = 0; j < kLen; j++) {
            pKeys[k * kLen + j] = pKeys[k * kLen * nPARALLEL + j];
        }
    }
}
    // Returns in the correct variable
    memcpy(K, pKeys, totalPasswords * kLen * sizeof (unsigned char));

    //========== Frees the Memory Matrix and Keys =============//
    cudaFree(memMatrixGPU);
    cudaFree(pkeysGPU);
    cudaFree(stateThreadGPU);
    cudaFree(stateIdxGPU);
    cudaFree(saltGPU);
    cudaFree(pwdGPU);

    //Free allKeys
    free(pKeys);
    pKeys = NULL;

    return result;
}
