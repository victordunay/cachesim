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
//    there is allways valid, and allways LRU. NO dirty bit when write-through 
    bool valid;
    bool dirty;
    bool LRU;

    status_t status;
} set_t;

typedef enum
{
    MISS = 0,
    HIT = 1,
} result_t;


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


typedef enum 
{
    READ = 0,
    WRITE = 1,
}operation_t;


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

    void get_tag_from_set(unsigned set_index, unsigned * tag)
    {
        *tag = sets[set_index].tag;
    }
    
    bool is_empty_set(unsigned set_index)
    {
        return !sets[set_index].status;
    }
    
    int get_value_from_cache(unsigned set_index, unsigned offset_in_block)
    {
        return sets[set_index].block[offset_in_block];
    }
 
    ~Way() {};
};

class CacheLevel
{
public:
    Way * ways;
    unsigned access_time;
    unsigned tag_mask;
    unsigned block_mask;
    unsigned set_mask;
    unsigned num_of_set_bits;
    unsigned num_of_tag_bits;
    unsigned set_offset_in_bits;
    unsigned tag_offset_in_bits;
    unsigned num_of_block_bits;
    unsigned num_of_sets;
    unsigned num_of_ways;
    miss_policy_t miss_policy;

    CacheLevel(unsigned num_of_ways, unsigned block_size_in_bytes, unsigned access_time, miss_policy_t miss_policy, unsigned cache_size_in_bytes)
    {
        this->miss_policy = miss_policy;
        this->access_time = access_time;
        this->num_of_ways = num_of_ways;
        calculate_num_of_sets(&num_of_sets, cache_size_in_bytes, block_size_in_bytes, num_of_ways);

        calculate_num_of_bits(num_of_sets, &num_of_set_bits);
        calculate_num_of_bits(block_size_in_bytes, &num_of_block_bits);
        num_of_tag_bits = 32 - num_of_block_bits - num_of_set_bits;
        set_offset_in_bits = num_of_block_bits;
        tag_offset_in_bits = num_of_block_bits + num_of_set_bits;

        calculate_mask(num_of_set_bits, &this->set_mask);
        calculate_mask(num_of_tag_bits, &this->tag_mask);
        calculate_mask(num_of_block_bits, &this->block_mask);
        
        ways = new Way[num_of_ways];
        for(unsigned way_index = 0; way_index < num_of_ways; way_index++) 
        {
            ways->initialize_way(num_of_sets, block_size_in_bytes);
        }
    }

    void get_tag_from_address(unsigned * tag, uint32_t address)
    {
        apply_mask_on_address(address, tag, tag_mask, tag_offset_in_bits);
    }

    void get_set_from_address(unsigned * set, uint32_t address)
    {
        apply_mask_on_address(address, set, set_mask, set_offset_in_bits);
    }

    void get_block_offset_from_address(unsigned * offset_in_block, uint32_t address)
    {
        apply_mask_on_address(address, offset_in_block, block_mask, 0);
    }

    void calculate_num_of_sets(unsigned * num_of_sets, unsigned cache_size_in_bytes, unsigned block_size_in_bytes, unsigned num_of_ways)
    {
        unsigned num_of_blocks = cache_size_in_bytes / block_size_in_bytes;
        *num_of_sets = num_of_blocks / num_of_ways;
    }

    void apply_mask_on_address(uint32_t address, unsigned * masked_address, unsigned mask, unsigned offset)
    {
        *masked_address = (address >> offset) & mask;
    }
        
    void calculate_mask(unsigned num_of_bits, unsigned * mask)
    {
       *mask = 0;
        while(num_of_bits > 0)
    	{
    		*mask = *mask << 1 | 1;
    		num_of_bits -= 1;
    	}
    }

    void calculate_num_of_bits(unsigned value, unsigned * num_of_bits)
    {
        *num_of_bits = 1;
        while(value > 2)
        {
            *num_of_bits += 1;
            value >>= 1;
        }
    }
    
    void search_address_in_cache(uint32_t address, int * value, result_t * result)
    {
        unsigned required_tag = 0;
        unsigned cache_tag = 0;
        unsigned set_index = 0;
        unsigned way_index = 0;
        unsigned offset_in_block = 0;
        *value = 0;
        *result = MISS;

        (void)get_tag_from_address(&required_tag, address);
        (void)get_set_from_address(&set_index, address);
        (void)get_block_offset_from_address(&offset_in_block, address);

        for (way_index = 0; way_index < num_of_ways; ++way_index)
        {
            ways[way_index].get_tag_from_set(set_index, &cache_tag);
            if (cache_tag == required_tag & !ways[way_index].is_empty_set(set_index))
            {
                *value = ways[way_index].get_value_from_cache(set_index, offset_in_block);
                *result = HIT; 
            }
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
        l1 = new CacheLevel(cache_parameters.l1_ways, cache_parameters.block_size_in_bytes, cache_parameters.l1_access_time, cache_parameters.miss_policy, cache_parameters.l1_size_in_bytes);
        l2 = new CacheLevel(cache_parameters.l2_ways, cache_parameters.block_size_in_bytes, cache_parameters.l2_access_time, cache_parameters.miss_policy, cache_parameters.l2_size_in_bytes);
    }   

    return_code_t operation_handler(operation_t operation, uint32_t address, int * value)
    {
        return_code_t return_code = UNINITIALIZED;
        result_t result = MISS;

        if (READ == operation)
        {
            read_handler(address, value, &result);
            if (MISS == result)
            {
                // get value from main memory
            }
        }
        else
        {
            write_handler(address, *value);
        }
        return_code = SUCCESS;

        return return_code;
    }
    
    void read_handler(uint32_t address, int * value, result_t * result)
    {

        (void)l1->search_address_in_cache(address, value, result);

        if (MISS == *result)
        {
            (void)l2->search_address_in_cache(address, value, result);
        }
    }
    void write_handler(uint32_t address, int value)
    {

    }
    ~Cache() {};
};
