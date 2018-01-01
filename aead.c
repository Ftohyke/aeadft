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

#include "aeadft.h"

static const uint_8 csprng_src[13] = "/dev/urandom";

/*
 * Global variables: key_prng, nonce_prng, auth_prng,
 * key_hex, nonce_hex, auth_hex.
 */

void
writehex_prngchunk (int f_dest, void *chunk)
{
  size_t strlen;
  unsigned char data_hex[MAX_POLY1305CHUNK_HEXSTR_LENGTH];

  data_hex = bin2hex (chunk, data_hex);
  write (f_dest, data_hex, MAX_POLY1305CHUNK_HEXSTR_LENGTH);
}

int
encrypt (do_aead enc_data, const char *credentials_dst,
         const char *plaintext_src, const char *ciphertext_dst)
{
  return encrypt (enc_data, credentials_dst, plaintext_src, ciphertext_dst, NULL);
}

int
encrypt (do_aead enc_data, const char *credentials_dst,
         const char *plaintext_src, const char *ciphertext_dst,
         const unsigned char *weakpk_src)
{
  /*
   * Credentials for AEAD and encapsulating container
   * with deniable encryption stored in a single file.
   */

  int fdcsprng,
      fdcred,
      fdweakpk;
  size_t weakpk_len;
  void *key_prng, *nonce_prng, *auth_prng;
  char *key_hex, *nonce_hex, *auth_hex,
       *weakpk;
  struct stat weakpk_fstat;

  fdcsprng = open (csprng_src, O_RDONLY);
  key_prng = calloc (MAX_POLY1305CHUNK_LENGTH, 1);
  nonce_prng = calloc (MAX_POLY1305CHUNK_LENGTH, 1);
  auth_prng = calloc (MAX_POLY1305CHUNK_LENGTH, 1);
  if (weakpk_src) {
    stat (weakpk_src, &weakpk_fstat);
    weakpk_len = MIN (weakpk_fstat.st_size, MAX_POLY1305WEAKPKSTR_LENGTH);
    weakpk_srcd = open (weakpk_src, O_RDWR, S_IRUSR);
    weakpk = read (weakpk_srcd, weakpk_len);
    close (weakpk_srcd);
    argon2_poly1305_key (weakpk, weakpk_len,
                         key_prng, MAX_POLY1305CHUNK_LENGTH,
                         fdcsprng);
  }
  cred_aead_encap_dst = open (credentials_dst, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
  lseek (cred_aead_encap_dst, 0, SEEK_END);
  read (fdcsprng, key_prng, MAX_POLY1305CHUNK_LENGTH);
  read (fdcsprng, nonce_prng, MAX_POLY1305CHUNK_LENGTH);
  read (fdcsprng, auth_prng, MAX_POLY1305CHUNK_LENGTH);
  writehex_prngchunk (cred_aead_encap_dst, key_prng);
  writehex_prngchunk (cred_aead_encap_dst, nonce_prng);
  writehex_prngchunk (cred_aead_encap_dst, auth_prng);
  gcry_aes_poly1305_encrypt (plaintext_in, ciphertext_out, key_prng, nonce_prng, auth_prng);

  if (weakpk_src)
    close(fdweakpk);
  close(fdcsprng);
  close(fdcred);
  return 0;
}

