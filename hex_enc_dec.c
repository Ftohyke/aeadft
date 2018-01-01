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

/*
 * Copyright (C) 2017-2019 John <mail john@nachtimwald.com>
 */

/*
 * Original source code provided by John <mail john@nachtimwald.com>.
 * See https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/ for details.
 */

int bin2hex(const unsigned char *bin/*, size_t len*/, char *hexchr/*, size_t &out_len*/)
{
  //char   *out; // static is much faster and also it safe to use for small data chunks
  size_t  i;

  if (bin == NULL /*|| len == 0*/)
    return -1;

  //out_len = len*2+1;// MAX_POLY1305CHUNK_HEXSTR_LENGTH
  //out = malloc(MAX_POLY1305CHUNK_HEXSTR_LENGTH);
  for (i=0; i<MAX_POLY1305CHUNK_LENGTH; i++) {
    out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
    out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
  }
  hexchr[MAX_POLY1305CHUNK_HEXSTR_LENGTH-1] = '\0';

  return 0;
}


int hexchr2bin(const char hex, char *out)
{
  if (out == NULL)
    return 0;

  if (hex >= '0' && hex <= '9') {
    *out = hex - '0';
  } else if (hex >= 'A' && hex <= 'F') {
    *out = hex - 'A' + 10;
  } else if (hex >= 'a' && hex <= 'f') {
    *out = hex - 'a' + 10;
  } else {
    return 0;
  }

  return 1;
}


size_t hexs2bin(const char *hex, unsigned char **out)
{
  size_t len;
  char   b1;
  char   b2;
  size_t i;

  if (hex == NULL || *hex == '\0' || out == NULL)
    return 0;

  len = strlen(hex);
  if (len % 2 != 0)
    return 0;
  len /= 2;

  *out = malloc(len);
  memset(*out, 'A', len);
  for (i=0; i<len; i++) {
    if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
      return 0;
    }
   (*out)[i] = (b1 << 4) | b2;
  }
  return len;
}

