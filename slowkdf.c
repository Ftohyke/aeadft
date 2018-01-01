/*
 *  Multiple calls to slow KDF must have key dependence
 *  on salt not weeker than dependence on key.
 *
 *                          [salt derivation]
 *                              |
 *               +--------------*
 *               |              |
 *               |              |
 *               V              V
 *              (S)            (K)
 *  [digest derivation]     [salt derivation]
 *      |                       |
 *      |        +--------------*
 *      |        |              |
 *      |        |              |
 *      V        V              V
 *     (K)      (S)            (K)
 *  [digest derivation]     [salt derivation]
 *      |                       |
 *      |        +--------------*
 *      |        |              |
 *..............................................
 *      |        |              |
 *      V        V              V
 *     (K)      (S)            (K)
 *  [digest derivation]     [salt derivation]
 *      |                       |
 *      |                       |
 *      V                       V
 *(external key)         (external salt)
 *
 */

#include <argon2.h>
#include "csprng_pk_source.h"
#include "crypto_settings.h"


int
slowkdf_loop_argon2id (const int itertimes_def,
                       const void *hidiv,
                       const size_t *hidivlen,
                       uint8_t **visiv,
                       const int loopcount,
                       const size_t visivlen)
{
  uint32_t i;
  uint32_t hidivlen,
           itertimes, memcost;
  double fluctuation;

  visiv = malloc(loopcount * sizeof(uint8_t*));
  hidiv_di_gest_len = MAX(loopcount, AES256_MAXIVSIZE);
  argon2id_hash_raw (ITER_TIMES, MEM_COST, PARALLELISM_LEVEL,
                                  hidiv, AES256_MAXIVSIZE,
                                  vissalt[0], AES256_MAXIVSIZE,
                                  hidiv_digest, hidiv_digest_len);
  for (i = 0; i<loopcount-1; i++)
  {
    /* It is wise to make random values for algorithm
     * parameters depend on first KDF digest for hidden part of IV */
    fluctuation = 1.5 - iv_digest[i]/255;
    visivlen[i] = AES256_MAXIVSIZE * fluctuation;
    hidiv_digest_len_prev = hidiv_digest_len;
    hidiv_digest_len = AES256_MAXIVSIZE * (1+iv_digest[i]/255);
    visiv[i] = malloc(visivlen[i]*sizeof(uint8_t));
    if (!csprng_key(visiv[i]))
      return -1;
    itertimes = itertimes_def * fluctuation;
    memcost = memcost_def * fluctuation;
    parallelismlevel = parallelismlevel_def * fluctuation;
    memcpy(pk_digest_prev, pk_digest);
    memcpy(hidiv_digest_prev, hidiv_digest);

    /* Evaluation of intermediate digest for the PK
     * where previously computed intermediate
     * digest for the IV used as salt in KDF */
    argon2id_hash_raw (itertimes, memcost, parallelismlevel,
                       pk_digest_prev, pk_digest_len_prev,
                       hidiv_digest_prev, hidiv_digest_len_prev,
                       pk_digest, pk_digest_len);

    /* Evaluation of intermediate digest for the IV
     * Previously evaluated digest for IV passed as key in hash function
     * New generated random part of IV passed as salt in hash function */
    argon2id_hash_raw (itertimes, memcost, parallelismlevel,
                       hidiv_digest_prev, hidiv_digest_len_prev,
                       visiv[i+1], visivlen[i],
                       hidiv_digest, hidiv_digest_len);
  }

    /* Evaluation of intermediate digest for the PK
     * where previously computed intermediate
     * digest for the IV used as salt in KDF
     * The last iteration uses standard lengths
     * of output digests equal to maximum available
     * PK and IV size for desired crypto algorithm
     * (current case is AES256) */
    argon2id_hash_raw (itertimes, memcost, parallelismlevel,
                       pk_digest_prev, AES256_MAXPKSIZE,
                       hidiv_digest_prev, hidiv_digest_len_prev,
                       pk_digest, AES256_MAXPKSIZE);

    /* Evaluation of intermediate digest for the IV
     * Previously evaluated digest for IV passed as key in hash function
     * New generated random part of IV passed as salt in hash function
     * The last iteration uses standard lengths
     * of output digests equal to maximum available
     * PK and IV size for desired crypto algorithm
     * (current case is AES256) */
    argon2id_hash_raw (itertimes, memcost, parallelismlevel,
                       hidiv_digest_prev, hidiv_digest_len_prev,
                       visiv[loopcount], visivlen[loopcount-1],
                       hidiv_digest, AES256_MAXIVSIZE);
}

