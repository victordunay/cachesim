/* 046267 Computer Architecture - Winter 20/21 - HW #2 */

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include "cache.cpp"

using std::FILE;
using std::string;
using std::cout;
using std::endl;
using std::cerr;
using std::ifstream;
using std::stringstream;

int main(int argc, char **argv) 
{
	return_code_t return_code = UNINITIALIZED;

	cache_t cache_parameters;
	
	unsigned l1_num_of_sets = 0;
	unsigned l2_num_of_sets = 0;
	unsigned l1_num_of_set_bits = 0;
	unsigned l2_num_of_set_bits = 0;
	unsigned l1_num_of_tag_bits = 0;
	unsigned l2_num_of_tag_bits = 0;

	memset(&cache_parameters, 0, sizeof(cache_t));

	if (argc < 19) {
		cerr << "Not enough arguments" << endl;
		return 0;
	}

	// Get input arguments

	// File
	// Assuming it is the first argument
	char* fileString = argv[1];
	ifstream file(fileString); //input file stream
	string line;
	if (!file || !file.good()) {
		// File doesn't exist or some other error
		cerr << "File not found" << endl;
		return 0;
	}

	unsigned MemCyc = 0, BSize = 0, L1Size = 0, L2Size = 0, L1Assoc = 0,
			L2Assoc = 0, L1Cyc = 0, L2Cyc = 0, WrAlloc = 0;

	for (int i = 2; i < 19; i += 2) {
		string s(argv[i]);
		if (s == "--mem-cyc") {
			MemCyc = atoi(argv[i + 1]);
		} else if (s == "--bsize") {
			BSize = atoi(argv[i + 1]);
		} else if (s == "--l1-size") {
			L1Size = atoi(argv[i + 1]);
		} else if (s == "--l2-size") {
			L2Size = atoi(argv[i + 1]);
		} else if (s == "--l1-cyc") {
			L1Cyc = atoi(argv[i + 1]);
		} else if (s == "--l2-cyc") {
			L2Cyc = atoi(argv[i + 1]);
		} else if (s == "--l1-assoc") {
			L1Assoc = atoi(argv[i + 1]);
		} else if (s == "--l2-assoc") {
			L2Assoc = atoi(argv[i + 1]);
		} else if (s == "--wr-alloc") {
			WrAlloc = atoi(argv[i + 1]);
		} else {
			cerr << "Error in arguments" << endl;
			return 0;
		}
	}

	cache_parameters.block_size_in_bytes = SHIFT_LEFT(BSize);
    cache_parameters.l1_ways = SHIFT_LEFT(L1Assoc);
    cache_parameters.l2_ways = SHIFT_LEFT(L2Assoc);
	cache_parameters.l1_size_in_bytes = SHIFT_LEFT(L1Size);
    cache_parameters.l2_size_in_bytes = SHIFT_LEFT(L2Size);
	cache_parameters.memory_access_time = MemCyc;
    cache_parameters.l1_access_time = L1Cyc;
	cache_parameters.l2_access_time = L1Cyc;
    cache_parameters.miss_policy = (miss_policy_t)WrAlloc;
	cache_parameters.l1 = NULL;
	cache_parameters.l1 = NULL;
	cache_parameters.l1_tags = NULL;
	cache_parameters.l2_tags = NULL;
	cache_parameters.l1_status = NULL;
	cache_parameters.l2_status = NULL;
	
	(void)calculate_num_of_sets(&cache_parameters.l1_sets, cache_parameters.l1_size_in_bytes, cache_parameters.block_size_in_bytes, cache_parameters.l1_ways);
	(void)calculate_num_of_sets(&cache_parameters.l2_sets, cache_parameters.l1_size_in_bytes, cache_parameters.block_size_in_bytes, cache_parameters.l1_ways);

	Cache cache(cache_parameters);


	// (void)calculate_num_of_sets(&l1_num_of_sets, cache_parameters.l1_size_in_bytes, cache_parameters.block_size_in_bytes, cache_parameters.l1_ways);
	// (void)calculate_num_of_sets(&l2_num_of_sets, cache_parameters.l2_size_in_bytes, cache_parameters.block_size_in_bytes, cache_parameters.l2_ways);
	
	// (void)calculate_num_of_set_bits(l1_num_of_sets, &l1_num_of_set_bits);
	// (void)calculate_num_of_set_bits(l2_num_of_sets, &l2_num_of_set_bits);
	// (void)calculate_num_of_tag_bits(l1_num_of_set_bits, BSize, &l1_num_of_tag_bits);
	// (void)calculate_num_of_tag_bits(l2_num_of_set_bits, BSize, &l2_num_of_tag_bits);


	// (void)calculate_mask(l1_num_of_set_bits, &cache_parameters.l1_set_mask);
	// (void)calculate_mask(l2_num_of_set_bits, &cache_parameters.l2_set_mask);
	// (void)calculate_mask(l1_num_of_tag_bits, &cache_parameters.l1_tag_mask);
	// (void)calculate_mask(l2_num_of_tag_bits, &cache_parameters.l2_tag_mask);
	// (void)calculate_mask(BSize, &cache_parameters.l1_offset_in_block_mask);
	// (void)calculate_mask(BSize, &cache_parameters.l2_offset_in_block_mask);

	// cache_parameters.l1_set_offset = BSize;
	// cache_parameters.l2_set_offset = BSize;
	// cache_parameters.l1_tag_offset = BSize + l1_num_of_tag_bits;
	// cache_parameters.l2_tag_offset = BSize + l2_num_of_tag_bits;

	// (void)cache_struct_allocation(&cache);
	// (void)assign_cache_parameters(&cache, cache_parameters);

	// (void)cache_memory_allocation(&cache->l1, cache->l1_ways, cache->l1_size_in_bytes);
	// (void)cache_memory_allocation(&cache->l2, cache->l2_ways, cache->l2_size_in_bytes);
	// (void)cache_tags_allocation(&cache->l1_tags, cache->l1_ways, cache->block_size_in_bytes, cache->l1_size_in_bytes);
	// (void)cache_tags_allocation(&cache->l2_tags, cache->l2_ways, cache->block_size_in_bytes, cache->l2_size_in_bytes);
	// (void)cache_set_status_allocation(&cache->l1_status, cache->l1_ways, cache->block_size_in_bytes, cache->l1_size_in_bytes);
	// (void)cache_set_status_allocation(&cache->l2_status, cache->l2_ways, cache->block_size_in_bytes, cache->l2_size_in_bytes);

	// (void)initialize_cache_memory(&cache->l1, cache->l1_ways, cache->l1_size_in_bytes);
	// (void)initialize_cache_memory(&cache->l2, cache->l2_ways, cache->l2_size_in_bytes);
	// (void)initialize_cache_tags(&cache->l1_tags, cache->l1_ways, cache->block_size_in_bytes, cache->l1_size_in_bytes);
	// (void)initialize_cache_tags(&cache->l2_tags, cache->l2_ways, cache->block_size_in_bytes, cache->l2_size_in_bytes);
	// (void)initialize_cache_set_status(&cache->l1_status, cache->l1_ways, cache->block_size_in_bytes, cache->l1_size_in_bytes);
	// (void)initialize_cache_set_status(&cache->l2_status, cache->l2_ways, cache->block_size_in_bytes, cache->l2_size_in_bytes);


	while (getline(file, line)) {

		stringstream ss(line);
		string address;
		char operation = 0; // read (R) or write (W)
		if (!(ss >> operation >> address)) {
			// Operation appears in an Invalid format
			cout << "Command Format error" << endl;
			return 0;
		}

		// DEBUG - remove this line
		cout << "operation: " << operation;

		string cutAddress = address.substr(2); // Removing the "0x" part of the address

		// DEBUG - remove this line
		cout << ", address (hex)" << cutAddress;

		unsigned long int num = 0;
		num = strtoul(cutAddress.c_str(), NULL, 16);

		// DEBUG - remove this line
		cout << " (dec) " << num << endl;

	}

	double L1MissRate;
	double L2MissRate;
	double avgAccTime;

	printf("L1miss=%.03f ", L1MissRate);
	printf("L2miss=%.03f ", L2MissRate);
	printf("AccTimeAvg=%.03f\n", avgAccTime);

cleanup:
	return 0;
}
