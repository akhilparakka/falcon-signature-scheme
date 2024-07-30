#include <iostream>
#include <iomanip>
#include <sstream>
#include "falcon.h"

// Function to convert a byte array to a hexadecimal string
std::string to_hex(const uint8_t *data, size_t length)
{
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

int main()
{
    // Initialize SHAKE256 context for RNG
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0)
    {
        std::cerr << "Failed to initialize RNG" << std::endl;
        return 1;
    }

    // Parameters
    unsigned logn = 9; // Falcon-512
    size_t privkey_len = FALCON_PRIVKEY_SIZE(logn);
    size_t pubkey_len = FALCON_PUBKEY_SIZE(logn);
    size_t tmp_len = FALCON_TMPSIZE_KEYGEN(logn);

    // Allocate buffers
    uint8_t *privkey = new uint8_t[privkey_len];
    uint8_t *pubkey = new uint8_t[pubkey_len];
    uint8_t *tmp = new uint8_t[tmp_len];

    // Generate key pair
    if (falcon_keygen_make(&rng, logn, privkey, privkey_len, pubkey, pubkey_len, tmp, tmp_len) != 0)
    {
        std::cerr << "Key generation failed" << std::endl;
        delete[] privkey;
        delete[] pubkey;
        delete[] tmp;
        return 1;
    }

    // Convert keys to hexadecimal strings
    std::string privkey_hex = to_hex(privkey, privkey_len);
    std::string pubkey_hex = to_hex(pubkey, pubkey_len);

    // Print keys
    std::cout << "Public key: " << pubkey_hex << std::endl;
    std::cout << "Private key: " << privkey_hex << std::endl;

    // Clean up
    delete[] privkey;
    delete[] pubkey;
    delete[] tmp;

    return 0;
}
