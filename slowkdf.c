/*
 * AEAD File Toolkit --- an utility providing symmetric and deniable
 * authenticated encryption with associated data for files and folders
 * Copyright (C) 2019 Konstantin Ignatiev
 *
 * This file is part of AEAD File Toolkit.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
*/

/*
 *  Multiple calls to slow KDF must have key dependence
 *  on salt not weeker than a dependence on key.
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

#include <stdlib.h>
#include <argon2.h>
#include <lapacke_utils.h>
#include "utils.h"
#include "crypto_settings.h"
#include "csprng_pk_source.h"


int
slowkdf_loop_argon2id (const int itertimes_def,
                       const void *hidiv,
                       const size_t *hidivlen,
                       uint8_t **visiv,
                       const int loopcount,
                       const int memcost_def,
                       const int parallelismlevel_def,
                       size_t * const visivlen,
                       void *hash, const size_t hashlen,
                       void *iv, const size_t ivlen)
{
  uint32_t i,
           itertimes,
           memcost, parallelismlevel;
  size_t hidiv_digest_len,
         hidiv_digest_len_prev,
         pk_digest_len,
         pk_digest_len_prev;
  double minmax_fluctuation,
         max_fluctuation;
  void *hidiv_digest,
       *hidiv_digest_prev,
       *pk_digest,
       *pk_digest_prev;

  visiv = malloc (loopcount * sizeof (uint8_t *));
  hidiv_digest_len = MAX (loopcount, AES256_MAXIVSIZE);
  hidiv_digest = malloc (hidiv_digest_len * sizeof (uint8_t *));
  argon2id_hash_raw (ITER_TIMES, MEM_COST, PARALLELISM_LEVEL,
                     hidiv, AES256_MAXIVSIZE,
                     visiv[0], AES256_MAXIVSIZE,
                     hidiv_digest, hidiv_digest_len);
  for (i = 0; i<loopcount-1; i++)
  {
    /* It is wise to make random values for algorithm
     * parameters depend on first KDF digest for hidden part of IV */
    minmax_fluctuation = 1.5 - ((uint8_t *)hidiv_digest)[i]/255;
    max_fluctuation = (1.0 + ((uint8_t *)hidiv_digest)[i]/255);
    visivlen[i] = AES256_MAXIVSIZE * minmax_fluctuation;
    pk_digest_len_prev = pk_digest_len;
    pk_digest_len = AES256_MAXPKSIZE * max_fluctuation;
    hidiv_digest_len_prev = hidiv_digest_len;
    hidiv_digest_len = AES256_MAXIVSIZE * max_fluctuation;
    visiv[i] = malloc(visivlen[i]*sizeof(uint8_t));
    /* TODO: do not forget to implement exception handling in GNU recommended manner */
    if (!csprng_key(visiv[i]))
      return -1;
    itertimes = itertimes_def * minmax_fluctuation;
    memcost = MAX (memcost_def, MEM_COST) * minmax_fluctuation;
    parallelismlevel = MAX (parallelismlevel_def, PARALLELISM_LEVEL) * minmax_fluctuation;
    memcpy (pk_digest_prev, pk_digest);
    memcpy (hidiv_digest_prev, hidiv_digest);

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

