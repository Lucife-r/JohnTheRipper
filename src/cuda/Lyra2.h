/**
 * Header file for the Lyra2 Password Hashing Scheme (PHS).
 *
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
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
#ifndef LYRA2_CUDA_H_
#define LYRA2_CUDA_H_

typedef unsigned char byte;

#define ROW_LEN_INT64 (BLOCK_LEN_INT64 * N_COLS)                //Total length of a row: N_COLS blocks
#define ROW_LEN_BYTES (ROW_LEN_INT64 * 8)                       //Number of bytes per row

#define PLAINTEXT_LENGTH		125
#define BINARY_SIZE			256  //BIARY_SIZE in Lyra2 is unlimited

int gpuMult(void *K, unsigned int kLen, unsigned char *passwords, unsigned int pwdlen, unsigned char *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nPARALLEL, unsigned int N_COLS, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize);

#endif /* LYRA2_H_ */
