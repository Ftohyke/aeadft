/*
 * encrypt_file.c --- Argon2 testing utility.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <argon2.h>

#define ITER_TIMES 2048
#define MEM_COST 8*1024
#define PARALLELISM_LEVEL 1
#define AES256_MAXKEYSIZE 32

int
main (int argc, char **argv)
{
  int i,
      csprng_src,
      digest_argon2_out;
  long length;
  void *digest_argon2id,
       *key_prng,
       *salt_prng;

  csprng_src = open ("/dev/urandom", O_RDONLY);
  digest_argon2_out = open ("argon2_digest.txt",
                            O_CREAT|O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  key_prng = malloc (AES256_MAXKEYSIZE+1);
  salt_prng = malloc (AES256_MAXKEYSIZE+1);
  digest_argon2id = malloc (AES256_MAXKEYSIZE+1);
  memset (key_prng, 0, AES256_MAXKEYSIZE);

  read (csprng_src, key_prng, AES256_MAXKEYSIZE);
  read (csprng_src, salt_prng, AES256_MAXKEYSIZE);
  ((char *) salt_prng)[AES256_MAXKEYSIZE] = 0;
  for (i = 0; i < AES256_MAXKEYSIZE+1; i++)
    printf ("%hhx ", ((char *) key_prng)[i]);
  printf("\n");
  if (argon2id_hash_raw (ITER_TIMES, MEM_COST,
                         PARALLELISM_LEVEL,
                         key_prng, AES256_MAXKEYSIZE,
                         salt_prng, AES256_MAXKEYSIZE,
                         digest_argon2id,
                         AES256_MAXKEYSIZE) != ARGON2_OK) {
    printf ("Error!\n");
    close (csprng_src);
    return -1;
  }
  else
    printf ("Success!\n");
  for (i = 0; i < AES256_MAXKEYSIZE+1; i++)
    printf ("%hhx ", ((char *) digest_argon2id)[i]);
  printf ("\n");
  write (digest_argon2_out, digest_argon2id, AES256_MAXKEYSIZE);

  close (csprng_src);
  close (digest_argon2_out);

  return 0;
}
