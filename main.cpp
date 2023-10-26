#include <stdio.h>
#include <assert.h>
#include <string.h>
#include<iostream>
#include <chrono>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_schnorr_adaptor.h>
#include <secp256k1_ecdsa_adaptor.h>

#include "utils.h"

int schnorr_adaptor_benchmark()
{
    using namespace std::chrono;

    unsigned char msg[12] = "Hello World";
    unsigned char msg_hash[32];
    unsigned char tag[11] = "Next World";
    unsigned char bob_seckey[32];
    unsigned char signature[64];

    unsigned char adaptor_signature[65];
    int is_signature_valid;
    int return_val;
    secp256k1_xonly_pubkey bob_pubkey;
    secp256k1_keypair bob_keypair;
    unsigned char auxiliary_rand[32];
    unsigned char t[32];
    unsigned char t_prime[32];

    secp256k1_pubkey Tpub;
    unsigned char T[33];
    size_t T_len = 33;

    unsigned char T_prime[33];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Create timers
    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;
    duration<double, std::milli> time_span;
    double total_time_extract_adaptor = 0;
    double total_time_extract_t = 0;
    double total_time_presign = 0;
    double total_time_generate_common_schnorr=0;

    for(int i = 0; i < 1000; i++) {

        if (!fill_random(t, sizeof(t))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        //生成T
        return_val = secp256k1_ec_pubkey_create(ctx, &Tpub, t);
        assert(return_val == 1);
        secp256k1_ec_pubkey_serialize(ctx, T, &T_len, &Tpub, SECP256K1_EC_COMPRESSED);
        assert(T_len == 33);

        if (!fill_random(bob_seckey, sizeof(bob_seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }

        if (!secp256k1_keypair_create(ctx, &bob_keypair, bob_seckey)) {
            printf("Couldn't generate keypair\n");
            return 1;
        }
        return_val = secp256k1_keypair_xonly_pub(ctx, &bob_pubkey, NULL, &bob_keypair);
        assert(return_val);

        return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
        assert(return_val);
        if (!fill_random(auxiliary_rand, sizeof(auxiliary_rand))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        t1 = high_resolution_clock::now();
        secp256k1_schnorrsig_sign32(ctx, signature, msg_hash, &bob_keypair, auxiliary_rand);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double>>(t2 - t1);
        total_time_generate_common_schnorr += time_span.count();

        // Time presign
        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_presign(ctx, adaptor_signature, msg_hash, &bob_keypair, T, NULL);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double>>(t2 - t1);
        total_time_presign += time_span.count();
        assert(return_val == 1);

        // Time extract_t
        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_extract_t(ctx, T_prime, adaptor_signature, msg_hash, &bob_pubkey);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double>>(t2 - t1);
        total_time_extract_t += time_span.count();
        assert(return_val == 1);
        assert(memcmp(T, T_prime, sizeof(T)) == 0);

        return_val = secp256k1_schnorr_adaptor_adapt(ctx, signature, adaptor_signature, t);
        assert(return_val == 1);

        is_signature_valid = secp256k1_schnorrsig_verify(ctx, signature, msg_hash, 32, &bob_pubkey);
        assert(is_signature_valid);

        // Time extract_adaptor
        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_extract_adaptor(ctx, t_prime, adaptor_signature, signature);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double>>(t2 - t1);
        total_time_extract_adaptor += time_span.count();
        assert(return_val == 1);
        assert(memcmp(t, t_prime, sizeof(t)) == 0);
    }

    std::cout << "Average time for secp256k1_schnorr_adaptor_extract_adaptor: " << total_time_extract_adaptor / 1000 << " ms" << std::endl;
    std::cout << "Total time for secp256k1_schnorr_adaptor_extract_adaptor: " << total_time_extract_adaptor << " ms" << std::endl;

    std::cout << "Average time for secp256k1_schnorr_adaptor_extract_t: " << total_time_extract_t / 1000 << " ms" << std::endl;
    std::cout << "Total time for secp256k1_schnorr_adaptor_extract_t: " << total_time_extract_t << " ms" << std::endl;

    std::cout << "Average time for secp256k1_schnorr_adaptor_presign: " << total_time_presign / 1000 << " ms" << std::endl;
    std::cout << "Total time for secp256k1_schnorr_adaptor_presign: " << total_time_presign << " ms" << std::endl;
    std::cout<<"Total time for generating common schnorr signature: "<<total_time_generate_common_schnorr<<" ms"<<std::endl;
    printf("Success!\n");

    return 0;
}
int ecdsa_adaptor_benchmark()
{

    unsigned char msg[32] = "Hello World";
    unsigned char bob_seckey[32];
    unsigned char adaptor_sig[162];
    int return_val;
    secp256k1_pubkey enckey;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    if (!fill_random(bob_seckey, sizeof(bob_seckey))) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    // Generate encryption key
    if (!secp256k1_ec_pubkey_create(ctx, &enckey, bob_seckey)) {
        printf("Couldn't generate encryption key\n");
        return 1;
    }

    // Generate ECDSA adaptor signature

}
int main(void) {

    schnorr_adaptor_benchmark();

}
