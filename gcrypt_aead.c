/*
 * AEAD File Toolkit - an utility providing symmetric and deniable
 * authenticated encryption with associated data for files and folders
 * Copyright (C) 2019 Konstantin Ignatiev
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

int
gcry_aes_poly1305_encrypt (int fd_src, int fd_dst, void *key_prng,
                           void *nonce_prng, void *auth_prng)
{
  size_t tag_len;
  void *tag;
  gcry_error_t     err_code;
  gcry_cipher_hd_t aead_cipher;

  tag = calloc (MAX_POLY1305TAG_LENGTH, 1);
  err_code = gcry_cipher_open (&aead_cipher,
                               GCRY_CIPHER_AES256,
                               GCRY_CIPHER_MODE_POLY1305,
                               GCRY_CIPHER_SECURE);
  if (err_code) {
    gcry_cipher_close (aead_cipher);
    printf ("Error occured: %s\nSource: %s\n",
            gcry_strerror (err_code),
            gcry_strsource (err_code));
    return -1;
  }

  err_code = gcry_cipher_setkey (aead_cipher, key_prng,
                                 MAX_POLY1305CHUNK_LENGTH);
  err_code = gcry_cipher_setiv (aead_cipher, nonce_prng,
                                MAX_POLY1305NONCE_LENGTH);
  err_code = gcry_cipher_authenticate (aead_cipher, auth_prng,
                                       MAX_POLY1305CHUNK_LENGTH);
  err_code = gcry_cipher_encrypt (aead_cipher, out_ciphertext,
                                  ciphertext_size, in_plaintext,
                                  plaintext_size);
  err_code = gcry_cipher_gettag (aead_cipher, tag,
                                 MAX_POLY1305TAG_LENGTH);
  gcry_cipher_close (aead_cipher);
  return 0;
}

