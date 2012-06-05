//
// Himitsu
// by sh0
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

static void pwhash_dump(char* name, unsigned char* data, unsigned int size)
{
    printf("%s = ", name);
    unsigned int i;
    for (i=0; i<size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void pwhash_mix(unsigned char* hash_target, unsigned char* hash_master)
{
    // Mix
    unsigned char hash_mix[SHA_DIGEST_LENGTH];
    int i;
    for (i=0; i<SHA_DIGEST_LENGTH; i++)
        hash_mix[i] = hash_target[i] ^ hash_master[i];
    //pwhash_dump("xor", hash_mix, sizeof(hash_mix));

    // Rehash
    unsigned char hash_final[SHA_DIGEST_LENGTH];
    SHA1(hash_mix, sizeof(hash_mix), hash_final);
    //pwhash_dump("sha1(xor)", hash_final, sizeof(hash_final));

    // Base64
    char b64_text[(SHA_DIGEST_LENGTH + 2) / 3 * 4 + 1];
    int b64_size = 0;
    int j;
    for (i=0; i<SHA_DIGEST_LENGTH - 2; i += 3) {
        unsigned int v = (hash_final[i + 2] << 16) | (hash_final[i + 1] << 8) | (hash_final[i]);
        for (j=0; j<4; j++) {
            unsigned int f = (v & 0x3f);
            v = v >> 6;
            static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901=";
            b64_text[b64_size++] = base64[f];
        }
    }
    b64_text[b64_size] = '\0';
    
    // Print
    printf("hash: %.12s\n", b64_text);
    
    // Zero memory
    memset(b64_text, 0, sizeof(b64_text));
    memset(hash_mix, 0, sizeof(hash_mix));
    memset(hash_final, 0, sizeof(hash_final));
}

int main(int argc, const char* argv[])
{
    // Check for target
    if (argc < 2) {
        printf("usage: pwhash target\n");
        return 1;
    }
    printf("target: %s\n", argv[1]);

    // Hash target
    unsigned char hash_target[SHA_DIGEST_LENGTH];
    SHA1(argv[1], strlen(argv[1]), hash_target);

    // Get master key
    char* kr_pass = getpass("master: ");
    if (strlen(kr_pass) > 0)
        if (kr_pass[strlen(kr_pass) - 1] == '\n')
            kr_pass[strlen(kr_pass) - 1] = '\0';
    
    // Hash master
    unsigned char hash_master[SHA_DIGEST_LENGTH];
    SHA1(kr_pass, strlen(kr_pass), hash_master);
    
    // Mix and print result
    //pwhash_dump("sha1(target)", hash_target, sizeof(hash_target));
    //pwhash_dump("sha1(master)", hash_master, sizeof(hash_master));
    pwhash_mix(hash_target, hash_master);
    
    // Zero memory
    memset(hash_target, 0, SHA_DIGEST_LENGTH);
    memset(hash_master, 0, SHA_DIGEST_LENGTH);
    
    // Return
    return 0;
}

