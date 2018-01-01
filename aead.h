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

#ifndef _AEADFT_H
#define _AEADFT_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <gcrypt.h>
#include <openssl/evp.h>

#define MAX_POLY1305CHUNK_LENGTH 32
#define MAX_POLY1305CHUNK_HEXSTR_LENGTH 65
#define MAX_POLY1305NONCE_LENGTH 12
#define MAX_POLY1305WEAKPKSTR_LENGTH 256

/* Type-unsafe min macro definition. */
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/* Function prototypes. */

typedef int (*lp_openssl_encgcm)(unsigned char *, int,
                                 unsigned char *, int,
                                 unsigned char *,
                                 unsigned char *, int,
                                 unsigned char *,
                                 unsigned char *);
typedef int (*do_aead)();

typedef struct OpenSSL_ProtoEncDec {} openssl_protoencdec ;
typedef struct Libgcrypt_ProtoEncDec {} libgcrypt_protoencdec ;

#endif /* _AEADFT_H */

