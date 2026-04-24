# SLH-DSA-SHA2-128-24 one-shot signer (fork of sphincs/sphincsplus ref)

CC       ?= cc
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -std=c99 -I.

# Select thash flavour: simple (FIPS 205) — avoid *_robust.c
THASH_SRC = thash_sha2_simple.c

SRC = address.c \
      fors.c \
      hash_sha2.c \
      merkle.c \
      randombytes.c \
      sha2.c \
      sign.c \
      utils.c \
      utilsx1.c \
      wots.c \
      wotsx1.c \
      $(THASH_SRC) \
      main.c

OBJ = $(SRC:.c=.o)

BIN = slhdsa-sha2-128-24

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BIN) *.o

.PHONY: all clean
