#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define SHIFT_LEFT(shift_iterations) (1 << shift_iterations)
#define BYTE_SIZE (8)

#define CHECK_SUCCESS(res)	                                \
  do{                                                  		\
 		if (SUCCESS != (res))								\
		{													\
			return_code = ERROR;							\
			goto cleanup;									\
		}                                      			    \
  	} while(0);	

#define FREE_PTR(ptr)    								    \
		if (NULL != (ptr))							     	\
		{													\
			ptr = NULL;										\
		}													\

#define CHECK_NULL(ptr)	                  	                \
  do{                                      		            \
 		if (NULL == (ptr))									\
		{													\
			return_code = ERROR;							\
			goto cleanup;									\
		}                                     			    \
  	} while(0);																

typedef enum
{
  ERROR = -1,
  SUCCESS = 0,
  UNINITIALIZED,
} return_code_t;

typedef enum
{
   NO_WRITE_ALLOCATE = 0,
   WRITE_ALLOCATE = 1
} miss_policy_t;

typedef enum
{
   EMPTY = 0,
   OCCUPIED = 1
} status_t;


typedef struct
{
    char * block;
    unsigned tag;
    status_t status;
} set_t;

typedef struct 
{
	unsigned block_size_in_bytes;
    unsigned l1_ways;
    unsigned l2_ways;
    unsigned l1_sets;
    unsigned l2_sets;
	unsigned l1_size_in_bytes;
    unsigned l2_size_in_bytes;
	unsigned memory_access_time;
    unsigned l1_access_time;
	unsigned l2_access_time;
    unsigned l1_set_mask;
    unsigned l1_set_offset;
    unsigned l1_tag_mask;
    unsigned l1_tag_offset;
    unsigned l1_offset_in_block_mask;
    unsigned l2_set_mask;
    unsigned l2_set_offset;
    unsigned l2_tag_mask;
    unsigned l2_tag_offset;
    unsigned num_of_sets;
    unsigned l2_offset_in_block_mask;
    miss_policy_t miss_policy;
    char ** l1;
    char ** l2;
    unsigned ** l1_tags;
    unsigned ** l2_tags;
    status_t ** l1_status;
    status_t ** l2_status;
}
cache_t;


class Way 
{
public:
    set_t * sets;

    Way() {};

    void initialize_way(unsigned num_of_sets, unsigned block_size_in_bytes)
    {
        sets = new set_t[num_of_sets];
        sets->block = new char[block_size_in_bytes];
        memset(sets, 0, sizeof(set_t));
    }
    ~Way() {};
};


class CacheLevel
{
public:
    Way * ways;
    CacheLevel(unsigned num_of_ways, unsigned block_size_in_bytes, unsigned num_of_sets)
    {
        ways = new Way[num_of_ways];
        for(unsigned way_index = 0; way_index < num_of_ways; way_index++) 
        {
            ways->initialize_way(num_of_sets, block_size_in_bytes);
        }
    }
    ~CacheLevel() {};
};

class Cache
{
public:
    CacheLevel * l1;
    CacheLevel * l2;

    Cache(cache_t cache_parameters)
    {
        l1 = new CacheLevel(cache_parameters.l1_ways, cache_parameters.block_size_in_bytes, cache_parameters.l1_sets);
        l2 = new CacheLevel(cache_parameters.l2_ways, cache_parameters.block_size_in_bytes, cache_parameters.l2_sets);
    }
    ~Cache() {};
};





// return_code_t cache_struct_allocation(cache_t ** cache);
// return_code_t assign_cache_parameters(cache_t ** cache, cache_t cache_parameters);
// return_code_t cache_memory_allocation(char *** cache, unsigned num_of_ways, unsigned cache_size_in_bytes);
// return_code_t cache_tags_allocation(unsigned *** cache_tags, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes);
// return_code_t cache_set_status_allocation(set_status_t *** cache_set_status, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes);
// void initialize_cache_memory(char *** cache, unsigned num_of_ways, unsigned cache_size_in_bytes);
// void initialize_cache_tags(unsigned *** cache_tags, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes);
// void initialize_cache_set_status(set_status_t *** cache_set_status, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes);
// void apply_mask_on_address(uint32_t address, unsigned * masked_address, unsigned mask, unsigned offset);
// void calculate_mask(unsigned num_of_bits, unsigned * mask);
// void calculate_num_of_tag_bits(unsigned num_of_set_bits, unsigned num_of_offset_bits, unsigned * num_of_tag_bits);
// void calculate_num_of_set_bits(unsigned num_of_sets, unsigned * num_of_set_bits);
// void calculate_num_of_sets(unsigned * num_of_sets, unsigned cache_size_in_bytes, unsigned block_size_in_bytes, unsigned num_of_ways);
// void calculate_mask(unsigned num_of_bits, unsigned * mask);

// return_code_t cache_memory_allocation(char *** cache, unsigned num_of_ways, unsigned cache_size_in_bytes)
// {
//   	return_code_t return_code = UNINITIALIZED;

// 	unsigned way_index = 0;
//     unsigned way_size_in_bytes = cache_size_in_bytes / num_of_ways;

//     *cache = (char **) malloc(num_of_ways * sizeof(char *));
//     CHECK_NULL(*cache);

//     for (way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         (*cache)[way_index] = (char *) malloc(way_size_in_bytes * sizeof(char));
//         CHECK_NULL((*cache)[way_index]);
// 	}

// 	return_code = SUCCESS;

// cleanup:

// 	if (SUCCESS != return_code)
// 	{
// 		for (way_index = 0; way_index < num_of_ways; ++way_index)
// 		{
// 			FREE_PTR((*cache)[way_index]);
// 		}
// 		FREE_PTR(*cache);
// 	}
	
// 	return return_code;
// }

// return_code_t cache_struct_allocation(cache_t ** cache)
// {
//     return_code_t return_code = UNINITIALIZED;

// 	*cache = (cache_t *) malloc(sizeof(cache_t));

// 	CHECK_NULL(*cache);

//     return_code = SUCCESS;

// cleanup:
// 	if (SUCCESS != return_code)
// 	{
// 		FREE_PTR(cache);
// 	}
	
// 	return return_code;
// }

// return_code_t assign_cache_parameters(cache_t ** cache, cache_t cache_parameters)
// {
// 	return_code_t return_code = UNINITIALIZED;

//     **cache = cache_parameters;


//     return_code = SUCCESS;

// cleanup:

// 	return return_code;
// }

// void initialize_cache_set_status(set_status_t *** cache_set_status, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes)
// {
//    	unsigned way_index = 0;
//     unsigned set_index = 0;
//     unsigned num_of_blocks = cache_size_in_bytes / block_size_in_bytes;
//     unsigned num_of_sets = num_of_blocks / num_of_ways;
    
//     for(way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         for (set_index = 0 ; set_index < num_of_sets; ++set_index)
//         {
//             (*cache_set_status)[way_index][set_index] = EMPTY;
//         }
//     }
// }

// void initialize_cache_tags(unsigned *** cache_tags, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes)
// {
//    	unsigned way_index = 0;
//     unsigned set_index = 0;
//     unsigned num_of_blocks = cache_size_in_bytes / block_size_in_bytes;
//     unsigned num_of_sets = num_of_blocks / num_of_ways;
    
//     for(way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         for (set_index = 0 ; set_index < num_of_sets; ++set_index)
//         {
//             (*cache_tags)[way_index][set_index] = 0;
//         }
//     }
// }


// void initialize_cache_memory(char *** cache, unsigned num_of_ways, unsigned cache_size_in_bytes)
// {
//     unsigned way_size_in_bytes = cache_size_in_bytes / num_of_ways;
// 	unsigned way_index = 0;
//     unsigned offset_in_way = 0;
    
//     for(way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         for (offset_in_way = 0 ; offset_in_way < way_size_in_bytes; ++offset_in_way)
//         {
//             (*cache)[way_index][offset_in_way] = 0;
//         }
//     }
// }

// return_code_t cache_set_status_allocation(set_status_t *** cache_set_status, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes)
// {
//   	return_code_t return_code = UNINITIALIZED;

// 	unsigned way_index = 0;
//     unsigned num_of_sets = 0;
//     (void)calculate_num_of_sets(&num_of_sets, cache_size_in_bytes, block_size_in_bytes, num_of_ways);


//     *cache_set_status = (set_status_t **) malloc(num_of_ways * sizeof(set_status_t *));
//     CHECK_NULL(*cache_set_status);

//     for (way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         (*cache_set_status)[way_index] = (set_status_t *) malloc(num_of_sets * sizeof(set_status_t));
//         CHECK_NULL((*cache_set_status)[way_index]);
// 	}

// 	return_code = SUCCESS;

// cleanup:

// 	if (SUCCESS != return_code)
// 	{
// 		for (way_index = 0; way_index < num_of_ways; ++way_index)
// 		{
// 			FREE_PTR((*cache_set_status)[way_index]);
// 		}
// 		FREE_PTR(*cache_set_status);
// 	}
	
// 	return return_code;
// }

// return_code_t cache_tags_allocation(unsigned *** cache_tags, unsigned num_of_ways, unsigned block_size_in_bytes, unsigned cache_size_in_bytes)
// {
//   	return_code_t return_code = UNINITIALIZED;

// 	unsigned way_index = 0;
//     unsigned num_of_sets = 0;
//     (void)calculate_num_of_sets(&num_of_sets, cache_size_in_bytes, block_size_in_bytes, num_of_ways);

//     *cache_tags = (unsigned **) malloc(num_of_ways * sizeof(unsigned *));
//     CHECK_NULL(*cache_tags);

//     for (way_index = 0; way_index < num_of_ways; ++way_index)
//     {
//         (*cache_tags)[way_index] = (unsigned *) malloc(num_of_sets * sizeof(unsigned));
//         CHECK_NULL((*cache_tags)[way_index]);
// 	}

// 	return_code = SUCCESS;

// cleanup:

// 	if (SUCCESS != return_code)
// 	{
// 		for (way_index = 0; way_index < num_of_ways; ++way_index)
// 		{
// 			FREE_PTR((*cache_tags)[way_index]);
// 		}
// 		FREE_PTR(*cache_tags);
// 	}
	
// 	return return_code;
// }

// void apply_mask_on_address(uint32_t address, unsigned * masked_address, unsigned mask, unsigned offset)
// {
//     *masked_address = (address >> offset) & mask;
// }

// void calculate_mask(unsigned num_of_bits, unsigned * mask)
// {
//    *mask = 0;
//     while(num_of_bits > 0)
// 	{
// 		*mask = *mask << 1 | 1;
// 		num_of_bits -= 1;
// 	}
// }

void calculate_num_of_sets(unsigned * num_of_sets, unsigned cache_size_in_bytes, unsigned block_size_in_bytes, unsigned num_of_ways)
{
    unsigned num_of_blocks = cache_size_in_bytes / block_size_in_bytes;
    *num_of_sets = num_of_blocks / num_of_ways;
}

// void calculate_num_of_set_bits(unsigned num_of_sets, unsigned * num_of_set_bits)
// {
//     *num_of_set_bits = 0;
//     while(num_of_sets > 1)
// 	{
// 		*num_of_set_bits += 1;
// 		num_of_sets >>= 1;
// 	}
// }

// void calculate_num_of_tag_bits(unsigned num_of_set_bits, unsigned num_of_offset_bits, unsigned * num_of_tag_bits)
// {
//     *num_of_tag_bits = BYTE_SIZE * sizeof(uint32_t) - num_of_set_bits - num_of_offset_bits;

// }
// 