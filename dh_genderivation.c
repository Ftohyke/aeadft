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

#include <unistd.h>
#include <argon2.h>

/* Custom values. */
#define ITER_TIMES 2048
#define MEM_COST 8*1024
#define PARALLELISM_LEVEL 1
/* Predefined values. */
#define AES256_MAXKEYSIZE 32
#define ARGON2_RECOMMENDEDSALTSIZE 16

int
argon2_poly1305_key (char *weakpk, size_t weakpk_len,
                     void *strongpk, size_t strongpk_len,
                     int csprng_srcd)
{
  int err_code;
  void *argon2_strongpk, *salt_prng;

  salt_prng = malloc (ARGON2_RECOMMENDEDSALTSIZE);
  read (csprng_srcd, strongpk, strongpk_len);
  for (size_t i = 0; i < weakpk_len; i += strongpk_len) {
    read (csprng_srcd, salt_prng, ARGON2_RECOMMENDEDSALTSIZE);
    err_code = argon2id_hash_raw (ITER_TIMES, MEM_COST, PARALLELISM_LEVEL,
                                  weakpk+i, strongpk_len,
                                  salt_prng, ARGON2_RECOMMENDEDSALTSIZE,
                                  argon2_strongpk, strongpk_len);
    if (err_code != ARGON2_OK)
      return -1;
    for (size_t j = 0; j < strongpk_len; j++)
      strongpk[j] =  strongpk[j] ^ argon2_strongpk[j];
  }
  return 0;
}

