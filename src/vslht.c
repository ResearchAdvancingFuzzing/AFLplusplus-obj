
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "vslht.h"

#define MAX_OCCUPANCY_FRACTION 0.75


Vslht *vslht_new(uint32_t size, HashFnT hash_fn, KeysEqualFnT keys_equal_fn,
                 KeyCopyFnT key_copy_fn, ValueCopyFnT value_copy_fn,
                 KeyPrintFnT key_print_fn) {
    Vslht *v = (Vslht *) malloc(sizeof(Vslht));
    v->num_bins = size;
    v->occ = 0;
    v->bin = (VslhtBin **) malloc(size * sizeof(VslhtBin*));
    for (uint32_t i=0; i<v->num_bins; i++)
        v->bin[i] = NULL;
    v->hash_fn = hash_fn;
    v->keys_equal_fn = keys_equal_fn;
    v->key_copy_fn = key_copy_fn;
    v->value_copy_fn = value_copy_fn;
    v->key_print_fn = key_print_fn;
    return v;
}

float occ_frac(Vslht *v) {
    return ((float)v->occ) / ((float)v->num_bins);
}

// add key-value pair.
// vslht basically retains a ref to these two pointer
// so it is *assumed* that they are not going to be freed!
// disallowed -- key is already in the vslht
// which means vslht_find should be called first to see if
// it is already there.
void vslht_add(Vslht *v, void *key, void *value) {
    // resize if needed
    if (occ_frac(v) > MAX_OCCUPANCY_FRACTION) {
//        printf ("resizing to %d bins\n", v->num_bins * 2);
        // double in size each time
        Vslht *nv = vslht_new(2*v->num_bins,v->hash_fn,v->keys_equal_fn,
                              v->key_copy_fn,v->value_copy_fn,v->key_print_fn);
        for (uint32_t i=0; i<v->num_bins; i++) {
            if (v->bin[i]) {
                VslhtBin *b = v->bin[i];
                vslht_add(nv, b->key, b->value);
            }
            free(v->bin[i]);
            // dont free b->key and b->value since they have just moved over to the new vslht
        }
        free(v->bin);
        v->num_bins = nv->num_bins;
        v->bin = nv->bin;
        free(nv);
    }  
    // default bin for this key
    uint32_t b = v->hash_fn(key) % v->num_bins;
    // linearly probe starting with b to find first empty bin
    // NB: presumes there are empty bins, i.e. occ not 100%
    while (true) {
        if (v->bin[b] == NULL) 
            // found empty bin -- we will put new entry here
            break;
        // found matching key which means we are trying to add key that's already there right?
        if (v->keys_equal_fn(key, v->bin[b]->key) == true) {
            printf ("keys equal? \n");
            printf ("key1: ");
            v->key_print_fn(key);
            printf("\nkey2: ");
            v->key_print_fn(v->bin[b]->key);
            printf("\n");
        }
        assert (v->keys_equal_fn(key, v->bin[b]->key) == false);
        b++;
        if (b==v->num_bins) b=0;
    }
    VslhtBin *bin = (VslhtBin *) malloc(sizeof(VslhtBin));
    bin->key = v->key_copy_fn(key);
    bin->value = v->value_copy_fn(value);
    v->bin[b] = bin;
    v->occ ++;
}



// returns the ptr to the value associated with this key
// or NULL if its isnt actually there
void *vslht_find(Vslht *v, void *key) {
    uint32_t b = v->hash_fn(key) % v->num_bins;
    // linearly probe starting with b to find key
    // or first empty bin indicating not there
    unsigned i = 0;
    while (true) {
        if (v->bin[b] == NULL) 
            // found empty bin.  Thus, key is not in v
            return NULL;
        if (v->keys_equal_fn(key, v->bin[b]->key) == true) 
            // found matching key
            return v->bin[b]->value;
        i++;
        // every bin has been examined
        if (i==v->num_bins) 
            break;
        b++;
        if (b==v->num_bins) 
            b=0;
    }
    return NULL;
}



// returns an array of ptrs to the keys in this hashtable
VslhtBin **vslht_data(Vslht *v) {
  return v->bin;
}


uint32_t vslht_num_bins(Vslht *v) {
    return v->num_bins;
}

VslhtBin *vslht_get_bin(Vslht *v, uint32_t ind) {
    assert (ind < v->num_bins);
    return v->bin[ind];
}


