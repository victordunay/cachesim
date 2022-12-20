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
    unsigned lru_index;
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

typedef char operation_t;


class Way 
{
public:
    set_t * sets;
    unsigned lru_index;
    unsigned num_of_sets;
    Way() {};

    void initialize_way(unsigned num_of_sets, unsigned block_size_in_bytes)
    {
        sets = new set_t[num_of_sets];
        sets->block = new char[block_size_in_bytes];
        memset(sets, 0, sizeof(set_t));
        this->num_of_sets = num_of_sets;
    }
    
    void initialize_lru_index(unsigned lru_index)
    {
        unsigned set_index = 0;
        for(set_index = 0; set_index < num_of_sets; ++set_index)
        {
            sets[set_index].lru_index = lru_index;
        }
        this->lru_index = lru_index;
    }
    void get_tag_from_set(unsigned set_index, unsigned * tag)
    {
        *tag = sets[set_index].tag;
    }
    
    bool is_valid_set(unsigned set_index)
    {
        return sets[set_index].valid;
    }
    
    int get_value_from_cache(unsigned set_index, unsigned offset_in_block)
    {
        return sets[set_index].block[offset_in_block];
    }
    
    bool is_dirty(unsigned set_index)
    {
        return sets[set_index].dirty;
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
    uint32_t block_address_mask;
    unsigned num_of_miss;
    unsigned num_of_access;

    CacheLevel(unsigned num_of_ways, unsigned block_size_in_bytes, unsigned access_time, unsigned cache_size_in_bytes)
    {
        this->access_time = access_time;
        this->num_of_ways = num_of_ways;
        this->num_of_miss = 0;
        this->num_of_access = 0;
        calculate_block_address_mask(block_size_in_bytes, &block_address_mask);

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
            ways[way_index].initialize_way(num_of_sets, block_size_in_bytes);
            ways[way_index].initialize_lru_index(way_index);
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
        *num_of_bits = 0;
        while(value > 1)
        {
            *num_of_bits += 1;
            value >>= 1;
        }
    }
    
    void find_empty_set_in_cache(unsigned set_index, unsigned * way_index_for_new_block, bool * found_empty_set)
    {
        unsigned way_index = 0;

        for (way_index = 0; way_index < num_of_ways; ++way_index)
        {
            if (0 == ways[way_index].sets[set_index].valid)
            {
               *way_index_for_new_block = way_index; 
               *found_empty_set = true;
               break;
            }
        }
    }
    void calculate_block_address_mask(unsigned block_size_in_bytes, uint32_t * block_address_mask)
    {
        *block_address_mask = 0xFFFFFFFF;
        while(block_size_in_bytes > 1)
        {
            *block_address_mask <<= 1;
            block_size_in_bytes >>= 1;
        }
    }
    void search_address_in_cache(uint32_t address, result_t * result, set_t ** set,bool enable_counter)
    {
        unsigned required_tag = 0;
        unsigned cache_tag = 0;
        unsigned set_index = 0;
        unsigned way_index = 0;
        unsigned offset_in_block = 0;
        *result = MISS;
        if (enable_counter)
        {
            num_of_access = num_of_access + 1;
        }
        (void)get_tag_from_address(&required_tag, address);
        (void)get_set_from_address(&set_index, address);
        (void)get_block_offset_from_address(&offset_in_block, address); // unused?

        for (way_index = 0; way_index < num_of_ways; ++way_index)
        {
            ways[way_index].get_tag_from_set(set_index, &cache_tag);
            if ((cache_tag == required_tag) & ways[way_index].is_valid_set(set_index))
            {
                *result = HIT;
                *set = &ways[way_index].sets[set_index];
            
                update_lru_states(way_index, set_index);
        
                break;               
            }
        }
        if (MISS == *result & enable_counter)
        {
            this->num_of_miss++;
        }
    }


    void get_lru_way_index(unsigned set_index, unsigned * way_index_for_new_block)
    {
        unsigned way_index = 0;
        *way_index_for_new_block = 0;

        for (way_index = 0; way_index < num_of_ways; ++way_index)
        {
            if (ways[*way_index_for_new_block].sets[set_index].lru_index < ways[way_index].sets[set_index].lru_index)
            {
                *way_index_for_new_block = way_index;
            }
        }
    }

    void update_lru_states(unsigned hit_way_index, unsigned set_index)
    {
        unsigned way_index = 0;
        unsigned current_lru_index = ways[hit_way_index].sets[set_index].lru_index;
        
        for (way_index = 0; way_index < num_of_ways; ++way_index)
        {
            if (ways[way_index].sets[set_index].lru_index < current_lru_index)
            {
                ways[way_index].sets[set_index].lru_index++;
            }
        }

        ways[hit_way_index].sets[set_index].lru_index = 0;
    }


    void calculate_address_of_evacuated_block(uint32_t * address_of_evacuated_block, unsigned tag_of_evacuated_block, unsigned set_of_evacuated_block)
    {
        *address_of_evacuated_block = (tag_of_evacuated_block << (num_of_set_bits + num_of_block_bits) | (set_of_evacuated_block << num_of_block_bits));
    }
    void free_block_from_lru_way(uint32_t address, set_t ** set_of_new_block, unsigned * set_index_of_new_block)
    {
        unsigned way_index_for_new_block = 0;
        unsigned way_index = 0;
        unsigned set_index = 0;
        bool found_empty_set = false;

        (void)get_set_from_address(&set_index, address);
        (void)find_empty_set_in_cache(set_index, &way_index_for_new_block, &found_empty_set);

        if (!found_empty_set)
        {
           (void)get_lru_way_index(set_index, &way_index_for_new_block);
        }
     
        *set_of_new_block = &ways[way_index_for_new_block].sets[set_index];
        *set_index_of_new_block = set_index;
        (void)update_lru_states(way_index_for_new_block, set_index);
    }


    void update_block(set_t * set_for_update, uint32_t address, bool update_dirty)
    {
        set_for_update->valid = 1;
        (void)get_tag_from_address(&set_for_update->tag, address);
        if (update_dirty)
        {
            set_for_update->dirty = 1;
        }
    }
    ~CacheLevel() {};
};

class Cache
{
public:
    CacheLevel * l1;
    CacheLevel * l2;
    unsigned l1_ways;
    unsigned l2_ways;
    unsigned block_size_in_bytes;
    miss_policy_t miss_policy;
 



    Cache(cache_t cache_parameters)
    {
        this->block_size_in_bytes = cache_parameters.block_size_in_bytes;
        this->l1_ways = cache_parameters.l1_ways;
        this->miss_policy = cache_parameters.miss_policy;
   
        l1 = new CacheLevel(cache_parameters.l1_ways, cache_parameters.block_size_in_bytes, cache_parameters.l1_access_time, cache_parameters.l1_size_in_bytes);
        l2 = new CacheLevel(cache_parameters.l2_ways, cache_parameters.block_size_in_bytes, cache_parameters.l2_access_time, cache_parameters.l2_size_in_bytes);
    }   

    return_code_t operation_handler(operation_t operation, uint32_t address)
    {
        return_code_t return_code = UNINITIALIZED;
        if ('r' == operation)
        {   
            read_handler(address);
        }
        else
        {
           write_handler(address);
        }
        return_code = SUCCESS;

        return return_code;
    }
    
    void read_handler(uint32_t address)
    {
        result_t result = MISS;
        unsigned tag_of_address = 0;
        unsigned set_index_of_new_block = 0;
        set_t * set_of_new_block;
        set_t * hit_set;
        uint32_t address_of_evacuated_block = 0;
    
        (void)l1->search_address_in_cache(address, &result, &hit_set, true);

        if (HIT == result)
        {
            return;
        }
        else
        {
            (void)l2->search_address_in_cache(address, &result, &hit_set, true);

            if (HIT == result)
            {
                       
                    (void)l1->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);

                    if(set_of_new_block->valid & set_of_new_block->dirty)
                    {
                        (void)l1->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                        (void)l2->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                        if (HIT == result)
                        {
                            hit_set->dirty = 1;
                        }
                    }
                    (void)l1->update_block(set_of_new_block, address, false);
                
            }
            else
            {
                                  
                    (void)l2->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);
                    if(set_of_new_block->valid)
                    {
                        if (set_of_new_block->dirty)
                        {
                            set_of_new_block->dirty = 0;
                        }
                        else
                        {
                            (void)l2->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                            (void)l1->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                            
                            if (HIT == result & hit_set->valid)
                            {
                                hit_set->dirty = 0;
                                hit_set->valid = 0;
                            }
                        }
                    }
                
                    (void)l2->update_block(set_of_new_block, address, false);
                   
                    (void)l1->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);
                    if(set_of_new_block->valid & set_of_new_block->dirty)
                    {
                        set_of_new_block->dirty = 0;

                        (void)l1->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                        (void)l2->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                        if (HIT == result)
                        {
                            hit_set->dirty = 1;
                        }
                    }
                    (void)l1->update_block(set_of_new_block, address, false);
                
            }
        }
    }

    void write_handler(uint32_t address)
    {
        result_t result = MISS;
        set_t * hit_set;
        set_t * set_of_new_block;
        unsigned set_index_of_new_block = 0;
        uint32_t address_of_evacuated_block = 0;
        unsigned tag_of_address = 0;


        (void)l1->search_address_in_cache(address, &result, &hit_set, true);

        if (HIT == result)
        {
            hit_set->dirty = 1;
            return;
        }
        else
        {
            (void)l2->search_address_in_cache(address, &result, &hit_set, true);

            if (HIT == result)
            {
                if (WRITE_ALLOCATE == miss_policy)
                {           
                    (void)l1->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);

                    if(set_of_new_block->valid & set_of_new_block->dirty)
                    {
                        (void)l1->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                        (void)l2->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                        
                        if (HIT == result)
                        {
                            hit_set->dirty = 1;
                        }

                    }
                    (void)l1->update_block(set_of_new_block, address, true);
                }
            }
            else
            {

                if (WRITE_ALLOCATE == miss_policy)
                {       
                    (void)l2->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);
                    if(set_of_new_block->valid)
                    {
                        if (set_of_new_block->dirty)
                        {
                            set_of_new_block->dirty = 0;
                        }
                        (void)l2->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                        (void)l1->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                        
                        if (HIT == result & hit_set->valid) //TODO checkalso of L1 is dirty
                        {
                            hit_set->dirty = 0;
                            hit_set->valid = 0;
                        }
                    }
                    (void)l2->update_block(set_of_new_block, address, false);
         
                    (void)l1->free_block_from_lru_way(address, &set_of_new_block, &set_index_of_new_block);
                    if(set_of_new_block->valid & set_of_new_block->dirty)
                    {
                            (void)l1->calculate_address_of_evacuated_block(&address_of_evacuated_block, set_of_new_block->tag, set_index_of_new_block);
                            (void)l2->search_address_in_cache(address_of_evacuated_block, &result, &hit_set, false);
                            if (HIT == result)
                            {
                                hit_set->dirty = 1;
                            }
                    }

                    (void)l1->update_block(set_of_new_block, address, true);
                }
            }
        }
    }
    ~Cache() {};
};
