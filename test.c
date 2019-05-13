
#include "api.h"
#include "randombytes.h"
#include "stm32wrapper.h"
#include <string.h>

#define NTESTS 30

/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
static void write_canary(unsigned char *d)
{
  *((uint64_t *) d)= 0x0123456789ABCDEF;
}

static int check_canary(unsigned char *d)
{
  if(*(uint64_t *) d !=  0x0123456789ABCDEF)
    return -1;
  else
    return 0;
}

static int test_keys(void)
{
  unsigned char key_a[CRYPTO_BYTES+16], key_b[CRYPTO_BYTES+16];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[CRYPTO_SECRETKEYBYTES+16];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);


  int i;

  for(i=0; i<NTESTS; i++)
  {
    //Alice generates a public key
    crypto_kem_keypair(pk+8, sk_a+8);
    send_USART_str("DONE key pair generation!");

    //Bob derives a secret key and creates a response
    crypto_kem_enc(sendb+8, key_b+8, pk+8);
    send_USART_str("DONE encapsulation!");

    //Alice uses Bobs response to get her secret key
    crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
    send_USART_str("DONE decapsulation!");

    if(memcmp(key_a+8, key_b+8, CRYPTO_BYTES))
    {
      send_USART_str("ERROR KEYS\n");
      return 1;
    }
    else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
            check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
            check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
            check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
            check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
    {
      send_USART_str("ERROR canary overwritten\n");
      return 1;
    }
    else
    {
      send_USART_str("OK KEYS\n");
    }
  }

  return 0;
}



int main(void)
{
  clock_setup(CLOCK_FAST);
  gpio_setup();
  usart_setup(115200);
  rng_enable();

  // marker for automated testing
  send_USART_str("==========================");

  test_keys();

  send_USART_str("#");

  while(1);

  return 0;
}
