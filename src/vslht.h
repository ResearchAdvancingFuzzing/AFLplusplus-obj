
#ifndef __VSLHT_H__
#define __VSLHT_H__
#include<stdint.h>
#include<stdbool.h>


typedef uint32_t (*HashFnT)(void *);
typedef bool (*KeysEqualFnT)(void *, void*);
typedef void * (*KeyCopyFnT)(void *);
typedef void * (*ValueCopyFnT)(void *);
typedef void (*KeyPrintFnT)(void *);

struct vslht_bin_struct {
  void *key;
  void *value;
};

typedef struct vslht_bin_struct VslhtBin;

struct vslht_struct {
  uint32_t num_bins;
  uint32_t occ; 
  // bins: array of keys and bins
  VslhtBin **bin;
  // the hash fn from key to uint32
  HashFnT hash_fn;
  // equals fn returns true if two keys equal
  KeysEqualFnT keys_equal_fn;
  // copy functions
  KeyCopyFnT key_copy_fn;
  ValueCopyFnT value_copy_fn;
  // key print 
  KeyPrintFnT key_print_fn;
};


typedef struct vslht_struct Vslht;


// create a new vslht
Vslht *vslht_new(uint32_t size, HashFnT hash_fn, KeysEqualFnT keys_equals_fn, KeyCopyFnT key_copy_fn, ValueCopyFnT value_copy_fn, KeyPrintFnT key_print_fn);


/*
 Add a key-value pair to the vslht. 

 Assumptions

 1. key,value will  *not* be freed by caller! vslht will not 
    copy key or value -- it just stores the pointers. 

 2. key is NOT already in the vslht. If it is found to be there
    already, an assertion will trigger.

 3. If vslht is found to be too small it will grow to accomodate
    new key,value pairs

*/
void vslht_add(Vslht *vslht, void *key, void *value);


// returns the ptr to the value associated with this key
// or NULL if key isn't actually there
void *vslht_find(Vslht *vslht, void *key);


// returns an array of ptrs to the keys in this hashtable
void **vslht_keys(Vslht *vslht);

// returns number of bins in this vslht
uint32_t vslht_num_bins(Vslht *v);

// get ind-th bin in this v
VslhtBin *vslht_get_bin(Vslht *v, uint32_t ind);



#endif
