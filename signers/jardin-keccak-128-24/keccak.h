/*
 * Minimal Keccak-256 (legacy 0x01 padding — same primitive as Solidity's
 * keccak opcode and Ethereum's `keccak256`, NOT NIST SHA3-256 which uses
 * 0x06 padding).
 */
#ifndef JARDIN_KECCAK_H
#define JARDIN_KECCAK_H

#include <stddef.h>
#include <stdint.h>

/* Compute keccak256(in[0..inlen-1]) into out[0..31]. */
void keccak256(uint8_t out[32], const uint8_t *in, size_t inlen);

#endif
