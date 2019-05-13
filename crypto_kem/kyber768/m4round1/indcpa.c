#include <string.h>
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "fips202.h"
#include "ntt.h"
#include "reduce.h"

/*************************************************
* Name:        gen_matrix_mult
*
* Description: Generates matrix on the fly while multiplying coefficient-wise
*              with a polyvec and accumulating into poly r
*
* Arguments:   - poly *r:                   pointer to result polynomial
*              - polyvec *b :               pointer to polyvec to multiply matrix with
*              - int i:                     index of row in matrix to be multiplied
*              - unsigned char *publicseed: pointer to publicseed used to generate matrix with
*              - int transposed:            boolean deciding whether A or A^T is generated
**************************************************/
void gen_matrix_mult_acc(poly *r,
                        polyvec *b,
                        int i,
                        const unsigned char *publicseed,
                        int transposed)
{

  int j;
  uint16_t val;
  uint32_t t;
  unsigned int pos=0, ctr;
  unsigned int nblocks=1;
  uint8_t buf[SHAKE128_RATE*nblocks];
  uint64_t state[25];
  unsigned char extseed[KYBER_SYMBYTES+2];

  for(j=0;j<KYBER_SYMBYTES;j++)
    extseed[j] = publicseed[j];

  for(j=0;j<KYBER_K;j++)
  {
    ctr = pos = 0;

    if(transposed)
    {
      extseed[KYBER_SYMBYTES]   = i;
      extseed[KYBER_SYMBYTES+1] = j;
    }
    else
    {
      extseed[KYBER_SYMBYTES]   = j;
      extseed[KYBER_SYMBYTES+1] = i;
    }

    shake128_absorb(state,extseed,KYBER_SYMBYTES+2);
    shake128_squeezeblocks(buf,nblocks,state);

    while(ctr < KYBER_N)
    {
      val = (buf[pos] | ((uint16_t) buf[pos+1] << 8)) & 0x1fff;
      if(val < KYBER_Q)
      {
        t = (uint32_t) b->vec[j].coeffs[ctr] * val;
        r->coeffs[ctr] = ((uint32_t) r->coeffs[ctr] + t) % KYBER_Q;
        ctr++;
      }
      pos += 2;

      if(pos > SHAKE128_RATE*nblocks-2)
      {
        nblocks=1;
        shake128_squeezeblocks(buf,nblocks,state);
        pos = 0;
      }
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(unsigned char *pk,
                   unsigned char *sk)
{
  polyvec skpv;
  poly pkp;

  unsigned char buf[KYBER_SYMBYTES+KYBER_SYMBYTES];
  unsigned char *publicseed = buf;
  unsigned char *noiseseed = buf+KYBER_SYMBYTES;

  int i;
  unsigned char nonce=0;

  randombytes(buf, KYBER_SYMBYTES);
  sha3_512(buf, buf, KYBER_SYMBYTES);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise(skpv.vec+i,noiseseed,nonce++);

  polyvec_ntt(&skpv);

  for(i=0;i<KYBER_K;i++)
  {
    poly_zeroize(&pkp);

    gen_matrix_mult_acc(&pkp, &skpv, i, publicseed, 0);

    poly_invntt(&pkp);

    poly_addnoise(&pkp,noiseseed,nonce++);

    polyvec_compress_poly(pk, &pkp, i);
  }

  polyvec_tobytes(sk, &skpv);

  for(i=0;i<KYBER_SYMBYTES;i++)
    pk[i+KYBER_POLYVECCOMPRESSEDBYTES] = publicseed[i];
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins)
{
  polyvec r;
  poly p;

  const unsigned char *publicseed = pk + KYBER_POLYVECCOMPRESSEDBYTES;

  int i;
  unsigned char nonce = 0;

  for(i=0;i<KYBER_K;i++)
    poly_getnoise(r.vec+i,coins,nonce++); // pv = r

  polyvec_ntt(&r); // pv = \hat{r}

  for(i=0;i<KYBER_K;i++)
  {
    poly_zeroize(&p);

    gen_matrix_mult_acc(&p, &r, i, publicseed, 1); // mult A^T[i] with \hat{r}

    poly_invntt(&p);

    poly_addnoise(&p, coins, nonce++); // add e_1[i]

    polyvec_compress_poly(c, &p, i); // compress u[i]
  }

  // calculate v now

  polyvec_decompress_poly(&p, pk, 0); // p = t[0]
  poly_ntt(&p); // p = \hat{t[0]}
  poly_pointwise(&r.vec[0], &p, &r.vec[0]); // mult \hat{t[0]} with \hat{r[0]}, store in r[0] because it's not used anymore

  for(i=1;i<KYBER_K;i++)
  {
    polyvec_decompress_poly(&p, pk, i); // p = t[i]
    poly_ntt(&p); // p = \hat{t[i]}
    poly_pointwise_acc(&r.vec[0], &p, &r.vec[i]); // mult \hat{t[i]} with \hat{r[i]}, acc into r[0]
  }

  poly_invntt(&r.vec[0]);

  poly_addnoise(&r.vec[0], coins, nonce++); // add e_2

  poly_frommsg(&p, m); // reuse p to hold message poly
  poly_add(&r.vec[0], &r.vec[0], &p); // add message

  poly_compress(c+KYBER_POLYVECCOMPRESSEDBYTES, &r.vec[0]); // compress v

}

static int cmp_poly_compress(const unsigned char *r, const poly *a)
{
  unsigned char rc = 0;
  uint32_t t[8];
  unsigned int i,j,k=0;

  for(i=0;i<KYBER_N;i+=8)
  {
    for(j=0;j<8;j++)
      t[j] = (((freeze(a->coeffs[i+j]) << 3) + KYBER_Q/2)/KYBER_Q) & 7;

    rc |= r[k]^(t[0]       | (t[1] << 3) | (t[2] << 6));
    rc |= r[k+1]^((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
    rc |= r[k+2]^((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
    k += 3;
  }
  return rc;
}

static int cmp_polyvec_compress_poly(const unsigned char *r, const poly *p, int i)
{
  unsigned char rc = 0;
  int j, k;
  uint16_t t[8];
  for(j=0;j<KYBER_N/8;j++)
  {
    for(k=0;k<8;k++)
      t[k] = ((((uint32_t)freeze(p->coeffs[8*j+k]) << 11) + KYBER_Q/2)/ KYBER_Q) & 0x7ff;

    rc |= r[352*i+11*j+ 0] ^ ( t[0] & 0xff);
    rc |= r[352*i+11*j+ 1] ^ ((t[0] >>  8) | ((t[1] & 0x1f) << 3));
    rc |= r[352*i+11*j+ 2] ^ ((t[1] >>  5) | ((t[2] & 0x03) << 6));
    rc |= r[352*i+11*j+ 3] ^ ((t[2] >>  2) & 0xff);
    rc |= r[352*i+11*j+ 4] ^ ((t[2] >> 10) | ((t[3] & 0x7f) << 1));
    rc |= r[352*i+11*j+ 5] ^ ((t[3] >>  7) | ((t[4] & 0x0f) << 4));
    rc |= r[352*i+11*j+ 6] ^ ((t[4] >>  4) | ((t[5] & 0x01) << 7));
    rc |= r[352*i+11*j+ 7] ^ ((t[5] >>  1) & 0xff);
    rc |= r[352*i+11*j+ 8] ^ ((t[5] >>  9) | ((t[6] & 0x3f) << 2));
    rc |= r[352*i+11*j+ 9] ^ ((t[6] >>  6) | ((t[7] & 0x07) << 5));
    rc |= r[352*i+11*j+10] ^ ((t[7] >>  3));
  }
  return rc;
}

#if (KYBER_POLYVECCOMPRESSEDBYTES != (KYBER_K * 352))
#error "indcpa_enc_cmp needs KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352)"
#else
int indcpa_enc_cmp(const unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins)
{
  unsigned char rc;
  polyvec r;
  poly p;

  const unsigned char *publicseed = pk + KYBER_POLYVECCOMPRESSEDBYTES;

  int i;
  unsigned char nonce = 0;

  for(i=0;i<KYBER_K;i++)
    poly_getnoise(r.vec+i,coins,nonce++); // pv = r

  polyvec_ntt(&r); // pv = \hat{r}

  for(i=0;i<KYBER_K;i++)
  {
    poly_zeroize(&p);

    gen_matrix_mult_acc(&p, &r, i, publicseed, 1); // mult A^T[i] with \hat{r}

    poly_invntt(&p);

    poly_addnoise(&p, coins, nonce++); // add e_1[i]

    rc |= cmp_polyvec_compress_poly(c, &p, i); // compress u[i]
  }

  // calculate v now

  polyvec_decompress_poly(&p, pk, 0); // p = t[0]
  poly_ntt(&p); // p = \hat{t[0]}
  poly_pointwise(&r.vec[0], &p, &r.vec[0]); // mult \hat{t[0]} with \hat{r[0]}, store in r[0] because it's not used anymore

  for(i=1;i<KYBER_K;i++)
  {
    polyvec_decompress_poly(&p, pk, i); // p = t[i]
    poly_ntt(&p); // p = \hat{t[i]}
    poly_pointwise_acc(&r.vec[0], &p, &r.vec[i]); // mult \hat{t[i]} with \hat{r[i]}, acc into r[0]
  }

  poly_invntt(&r.vec[0]);

  poly_addnoise(&r.vec[0], coins, nonce++); // add e_2

  poly_frommsg(&p, m); // reuse p to hold message poly
  poly_add(&r.vec[0], &r.vec[0], &p); // add message

  rc |= cmp_poly_compress(c+KYBER_POLYVECCOMPRESSEDBYTES, &r.vec[0]); // compress v
  return rc;
}
#endif
/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void __attribute__ ((noinline)) indcpa_dec(unsigned char *m,
                                           const unsigned char *c,
                                           const unsigned char *sk)
{
  poly mp, p, skp;

  int i;

  poly_zeroize(&mp);

  for(i=0;i<KYBER_K;i++)
  {
    polyvec_decompress_poly(&p, c, i);

    poly_ntt(&p);

    poly_frombytes(&skp, sk+i*KYBER_POLYBYTES);

    poly_pointwise_acc(&mp, &p, &skp);
  }

  poly_invntt(&mp);

  poly_decompress(&p, c+KYBER_POLYVECCOMPRESSEDBYTES);

  poly_sub(&mp, &mp, &p);

  poly_tomsg(m, &mp);
}
