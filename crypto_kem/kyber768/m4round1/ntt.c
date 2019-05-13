#include "inttypes.h"
#include "ntt.h"
#include "params.h"
#include "reduce.h"

extern const uint16_t omegas_inv_bitrev_montgomery[];
extern const uint16_t psis_inv_montgomery[];
extern const uint16_t zetas[];
extern const uint16_t zetas_exp_asm[];
extern const uint16_t zetas_inv_exp_asm[];

extern void ntt_fast(uint16_t* poly, const uint16_t* zetas);
extern void invntt_fast(uint16_t* poly, const uint16_t* invzetas);

/*************************************************
* Name:        ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *p: pointer to in/output polynomial
**************************************************/
void ntt(uint16_t *p)
{
  ntt_fast(p, zetas_exp_asm);
}

/*************************************************
* Name:        invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void invntt(uint16_t * a)
{
  invntt_fast(a, zetas_inv_exp_asm);
}
