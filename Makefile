# Copyright (C) 2019 Konstantin Ignatiev
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

RM=rm -fv
CC=g++
CFLAGS=-I.
LDLIBS=-lm -largon2 -lrt -ldl
MODULES=encrypt_file
OBJS=$(patsubst %,%.o,${MODULES})

%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

dh_genderivation: ${OBJS}
	$(CC) -o dh_genderivation.elf ${OBJS} $(LDLIBS)

all: encrypt_file

clean:
	$(RM) *.o *.elf *.txt

.PHONY: all
