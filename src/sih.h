
#ifndef __SIH_H__
#define __SIH_H__

#include "vslht.h"

// a string that knows its own length
struct string_struct {
  char *str;
  uint32_t len;
};

typedef struct string_struct String;

// create a new sih of this initial size
Vslht *sih_new(uint32_t num_bins);

// add this key to the sih
// copies key and value (allocating memory)
// before adding. 
// do not call this with a key that is already in v.
void sih_add(Vslht *v, char *key, int val);

// returns true if key is in hash
bool sih_mem(Vslht *v, char *key);

// dont try to call this on a key that isnt in v!
// use sih_mem first
uint32_t sih_find(Vslht *v, char *key);



#endif
