#include "sha256.h"

#define WORD_ARR_SIZE(X) (sizeof(X) / sizeof(word))

int main(void) {
  word res[8] = {0};
  // abc
  sha256_compute("abc", res, WORD_ARR_SIZE(res));
  // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
  sha256_print(res, WORD_ARR_SIZE(res));
}
