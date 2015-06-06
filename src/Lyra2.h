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
#ifndef LYRA2_H_
#define LYRA2_H_

typedef unsigned char byte ;

extern unsigned short N_COLS;
extern int nCols_is_2_power;

struct lyra2_allocation{
    uint64_t **memMatrix;
    unsigned char **pKeys;
    uint64_t **threadSliceMatrix;
    unsigned char **threadKey;
    uint64_t **threadState;

    int64_t *gap;                //Modifier to the step, assuming the values 1 or -1
    uint64_t *step;              //Visitation step (used during Setup and Wandering phases)
    uint64_t *window;            //Visitation window (used to define which rows can be revisited during Setup)
    uint64_t *sync;              //Synchronize counter
    uint64_t *sqrt;              //Square of window (i.e., square(window)), when a window is a square number;
    uint64_t *row0;              //row0: sequentially written during Setup; randomly picked during Wandering
    uint64_t *prev0;             //prev0: stores the previous value of row0
    uint64_t *rowP;              //rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
    uint64_t *prevP;             //prevP: stores the previous value of rowP
    uint64_t *jP;                //Starts with threadNumber.
    uint64_t *kP;
    uint64_t *off0;
    uint64_t *offP;
    uint64_t *sliceStart;
    uint64_t **ptrWord;
};

int LYRA2_(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated);

int LYRA2_for_nThreads1(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, struct lyra2_allocation *allocated);

int LYRA2(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated);

#endif /* LYRA2_H_ */ 
