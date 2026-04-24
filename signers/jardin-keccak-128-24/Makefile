# JARDIN-Keccak-128-24 one-shot signer

CC      ?= cc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic -std=c99 -I.

SRC = address.c \
      fors.c \
      hash_keccak.c \
      keccak.c \
      merkle.c \
      randombytes.c \
      sign.c \
      thash_keccak.c \
      utils.c \
      utilsx1.c \
      wots.c \
      wotsx1.c \
      main.c

OBJ = $(SRC:.c=.o)
BIN = jardin-keccak-128-24

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BIN) *.o

.PHONY: all clean
