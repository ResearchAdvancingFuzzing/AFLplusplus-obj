
#include <stdlib.h>
#include <string.h>
#include "sih.h"

uint32_t seed=0x12345678;

// these 2 are from wikipedia...
static inline uint32_t murmur_32_scramble(uint32_t k) {
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	uint32_t h = seed;
    uint32_t k;
    /* Read in groups of 4. */
    for (size_t i = len >> 2; i; i--) {
        // Here is a source of differing results across endiannesses.
        // A swap here has no effects on hash properties though.
        memcpy(&k, key, sizeof(uint32_t));
        key += sizeof(uint32_t);
        h ^= murmur_32_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    /* Read the rest. */
    k = 0;
    for (size_t i = len & 3; i; i--) {
        k <<= 8;
        k |= key[i - 1];
    }
    // A swap is *not* necessary here because the preceding loop already
    // places the low bytes in the low places according to whatever endianness
    // we use. Swaps only apply when the memory is copied in a chunk.
    h ^= murmur_32_scramble(k);
    /* Finalize. */
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}



// return String containing str which is len characters
String * str_new(char *str, uint32_t len) {
  String *s = (String *) malloc(sizeof(String));
  s->len = len;
  s->str = strndup(str, len);
  return s;
}

void str_free(String *str) {
    free(str->str);
    free(str);
}

// for string keys
uint32_t str_hash(void *vkey) {
  String *key_str = (String *) vkey;
//  const uint8_t *ku = (const uint8_t *) key_str->str;
  return murmur3_32((uint8_t *) key_str->str, key_str->len, seed);
}

bool strs_equal(void *vkey1, void *vkey2) {
  String *key1_str = (String *) vkey1;
  String *key2_str = (String *) vkey2;
  if (key1_str->len != key2_str->len) return false;
  if (0 == strncmp(key1_str->str,key2_str->str,key1_str->len))
    return true;
  return false;
}

void *str_copy(void *vkey) {
  String *key_str = (String *) vkey;
  String *copy = (String *) malloc(sizeof(String));
  copy->len = key_str->len;
  copy->str = strndup(key_str->str, key_str->len);
  return (void *) copy;
}

void str_print(void *vkey) {
    String *key_str = (String *) vkey;
    printf ("%s", key_str->str);
}

void *int_new(int x) {
  int *v = (int*) malloc(sizeof(int));
  *v = x;
  return v;
}

void *int_copy(void *vkey) {
  int *iv = (int *) vkey;
  int *copy = (int *) malloc(sizeof(int));
  *copy = *iv;
  return (void *) copy;
}




Vslht *sih_new(uint32_t num_bins) {
    return vslht_new(num_bins, str_hash, strs_equal, str_copy, int_copy, str_print);
}

// key can be freed by caller since it is copied here.
// do not call this with a key that is already in v.
void sih_add(Vslht *v, char *key, int val) {
  String *str_key = str_new(key,strlen(key));
  int *val_ptr = int_new(val);
  vslht_add(v, str_key, val_ptr);
}


bool sih_mem(Vslht *v, char *key) {
    String *str_key = str_new(key,strlen(key));
    void *i = vslht_find(v, str_key);
    str_free(str_key);
    if (i==NULL) return false;
    return true;
}

uint32_t sih_find(Vslht *v, char *key) {
    String *str_key = str_new(key,strlen(key));
    uint32_t *i = (uint32_t *) vslht_find(v, str_key);
    str_free(str_key);
    // dont try to find something for a key not in the hash!
    return *i;
}

