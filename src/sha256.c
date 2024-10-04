#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * SHA-256 Functions
 * @brief SHA-256 uses six logical functions, where each function operates on
 * 32-bit words. The result of each function is a new 32 bit word.
 */
#define ROTR(X, N)                                                             \
  (((X) >> (N)) |                                                              \
   ((X) << (32 - (N)))) /* Circular shift of X by N positions to the right */
#define ROTL(X, N)                                                             \
  (((X) << (N)) |                                                              \
   ((X) >> (32 - (N)))) /* Circular shift of X by N positions to the left */

#define SHR(X, N) ((X) >> N) /* Right shift of X by N */
#define CH(X, Y, Z)                                                            \
  (((X) & (Y)) ^ (~(X) & (Z))) /* X Chooses if the output is Y or Z */
#define MAJ(X, Y, Z)                                                           \
  (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z))) /* Majority bit */
#define EPSI0(X)                                                               \
  (ROTR(X, 2) ^ ROTR(X, 13) ^ ROTR(X, 22)) /* Epsilon ^ 256 _ 0 */
#define EPSI1(X)                                                               \
  (ROTR(X, 6) ^ ROTR(X, 11) ^ ROTR(X, 25))               /* Epsilon ^ 256 _ 1 */
#define SIG0(X) (ROTR(X, 7) ^ ROTR(X, 18) ^ (SHR(X, 3))) /* Sigma ^ 256 _ 0 */
#define SIG1(X)                                                                \
  (ROTR(X, 17) ^ ROTR(X, 19) ^ (SHR(X, 10))) /* Sigma ^ 256 _ 1                \
                                              */

/**
 * MACROS
 */
#define CEIL(X, B)                                                             \
  ((X + B - 1) / B) /* Calculates Ceiling of X divided by bits B */

/**
 * SHA-256 Constants (K ^ 256)
 * @brief SHA-256 uses a sequence of 64 constant 32-bit words.
 */
static const word K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/**
 * SHA-256 Preprocessing
 * Three stages
 * 1. Padding the message
 * 2. Parsing the padded message into message blocks
 * 3. Setting the initial hash value H^0
 *  main idea: 32 bit msg blocks
 *  msg = a ~ 0b0110 0001
 *  msg_len = 1
 *  msg_bits = 8
 *  msg_block -> | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 * 0 | ... | * 13 * | ... | preprocess -> | 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 * 0 0 0 0 0 0 0 0 0 0 0 0 0 | ... | * 13 * | ... 1 0 0 0 |
 */
void sha256_preprocess_(const char *msg, word *block, const size_t msg_block_size) {
  const size_t msg_len = strlen(msg);
  const word msg_bits = msg_len * 8;
  const word word_bits = sizeof(word) * 8;
  const word word_msg_amount = CEIL(msg_bits, word_bits); /* Must have > to fit msg */

  if (word_msg_amount > msg_block_size) {
    printf("Not enough space.");
    exit(0);
  }

  size_t bit_i = 0;
  for (size_t i = 0; i < msg_len; ++i) {
    const char curr_char = msg[i];
    for (size_t bit = 8; bit > 0; bit--) {
      const size_t block_i = bit_i / word_bits;
      const size_t bit_pos = (word_bits - 1) - (bit_i % word_bits);
      const word bit_val = (curr_char >> (bit - 1)) & 1;
      block[block_i] |= bit_val << bit_pos;
      bit_i++;
    }
  }
  block[word_msg_amount - 1] |= (1 << ((word_bits - 1) - (msg_bits % word_bits)));

  // WARNING: Only goes up to 2^32 numbers...
  block[15] = msg_bits;
}

static word H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// WARNING: Only takes one message block..
// TODO: Add possibility for more message blocks:
// Example B.2 SHA-256 (Multi block message)
void sha256_compute(const char *msg, word *res, const size_t res_size) {
  const size_t block_amount = 16;
  word *block = (word *)malloc(sizeof(word) * block_amount);
  if (block  == NULL) {
    printf("Memory allocation failed.");
    exit(0);
  }

  for (size_t i = 0; i < block_amount; i++) {
    block[i] = 0;
  }

  sha256_preprocess_(msg, block, (sizeof(word) * block_amount));

  word w[64] = {0};
  for (size_t i = 0; i < 64; i++) {
    if (i <= 15) {
      w[i] = block[i];
      continue;
    }
    w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
  }
  free(block);
  word a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
               g = H[6], h = H[7];

  for (size_t i = 0; i < 64; i++) {
    const word t1 = h + EPSI1(e) + CH(e, f, g) + K[i] + w[i];
    const word t2 = EPSI0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;

  for (size_t i = 0; i < res_size; i++) {
    res[i] = H[i];
  }
}

void sha256_print(const word *res, const size_t res_size) {
  printf("Result: ");
  for (size_t i = 0; i < res_size; i++) {
    printf("%04x ", res[i]);
  }
  printf("\n");
}

