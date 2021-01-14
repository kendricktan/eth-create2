#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "sha3.h"

static void help(const char *argv0) {
    printf("To call: %s [DEPLOYER ADDRESS] [KECCAK256(bytecode)] [ADDRESS PATTERN] \n", argv0);
}

char* concat(const char *s1, const char *s2)
{
    uint size = strlen(s1) + strlen(s2) + 1;
    char *result = malloc(size);
    snprintf(result, size, "%s%s", s1, s2);
    return result;
}

char* slice_str(const char * str, size_t start, size_t end)
{
    char * buffer = malloc(end - start);

    size_t j = 0;

    for ( size_t i = start; i <= end; ++i ) {
        buffer[j++] = str[i];
    }
    buffer[j] = 0;

    return buffer;
}

static char* byte_to_hex(uint8_t b) {
    char *s = malloc(3);

    unsigned i=1;

    s[0] = s[1] = '0';
    s[2] = '\0';
    while(b) {
        unsigned t = b & 0x0f;
        if( t < 10 ) {
            s[i] = '0' + t;
        } else {
            s[i] = 'a' + t - 10;
        }
        i--;
        b >>= 4;
    }

    return s;
}

static char* to_hex(const uint8_t *hash) {
    char* result = "";

    for(unsigned i=0; i<32; i++) {
        result = concat(
            result,
            byte_to_hex(hash[i])
        );
    }

    return result;
}

bool starts_with(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

char* keccak256_solidity(uint8_t *in) {
    // Keccak 256 context
    sha3_context c;
    const uint8_t *hash;

    // Use Keccak256
    sha3_Init256(&c);
    enum SHA3_FLAGS flags2 = sha3_SetFlags(&c, SHA3_FLAGS_KECCAK);
    if( flags2 != SHA3_FLAGS_KECCAK )  {
        printf("Failed to set Keccak mode");
        exit(2);
    }

    // Perform Keccak256
    sha3_Update(&c, in, sizeof in);
    hash = sha3_Finalize(&c);
    char *result = to_hex(hash);

    return result;
}

char* to_bytes32(uint salt) {
    char *buf = malloc(65);
    
    sprintf(buf, "%064x", salt);

    return buf;
}

int main(int argc, char *argv[]) {
    // CLI Params
    char *deployer;
    char *bytecodeHash;
    char *pattern;

    if(argc != 4) {
	    help(argv[0]);
	    return 1;
    }

    deployer = argv[1];
    bytecodeHash = argv[2];
    pattern = argv[3];

    // Remove 0x
    if (starts_with(deployer, "0x")) {
        deployer = slice_str(deployer, 2, strlen(deployer) + 1);
    }
    if (starts_with(bytecodeHash, "0x")) {
        bytecodeHash = slice_str(bytecodeHash, 2, strlen(bytecodeHash) + 1);
    }

    uint salt = 10;
    char *part1 = concat("0xff", deployer);
    char *part2 = concat(part1, to_bytes32(salt));
    char *part3 = concat(part2, bytecodeHash);

    char* result = keccak256_solidity(part3);

    return 0;
}