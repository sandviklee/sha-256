/**
 * @file sha256.h
 * @Author Simon Sandvik Lee (sandviklee.dev)
 *
 * @brief Implementation of the Secure hashing algorithm "SHA-256"
 * @Details *
 * SHA-256 operate on 32-bit words.
 * Each message block has 512 bits.
 * http://csrc.nist.gov/publications/fips/fips180-2/fips1hh80-2withchangenotice.pdf
 */
// Created by Simon Sandvik Lee on 01/10/2024
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t word;
void sha256_preprocess_(const char *msg, word *block, const size_t msg_block_size);
void sha256_compute(const char *msg, word *res, const size_t res_size);
void sha256_print(const word *res, const size_t res_size);

#endif //SHA256_H
