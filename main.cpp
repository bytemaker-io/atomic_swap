#include <iostream>
#include <chrono>
#include <secp256k1_ecdsa_adaptor.h>
#include <secp256k1_schnorr_adaptor.h>
#include <secp256k1_schnorrsig.h>
#include <cassert>
#include "utils.h"

int schnorr_adaptor_benchmark() {
    using namespace std::chrono;

    unsigned char msg[12] = "Hello World";
    unsigned char msg_hash[32];
    unsigned char tag[11] = "Next World";
    unsigned char bob_seckey[32];
    unsigned char signature[64];
    unsigned char adaptor_signature[65];
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
    int return_val;
    int is_signature_valid;

    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;
    duration<double, std::milli> time_span;

    double total_time_extract_adaptor = 0;
    double total_time_extract_t = 0;
    double total_time_presign = 0;
    double total_time_generate_common_schnorr = 0;

    for(int i = 0; i < 1000; i++) {
        if (!fill_random(t, sizeof(t))) {
            std::cout << "Failed to generate randomness\n";
            return 1;
        }

        return_val = secp256k1_ec_pubkey_create(ctx, &Tpub, t);
        assert(return_val == 1);
        secp256k1_ec_pubkey_serialize(ctx, T, &T_len, &Tpub, SECP256K1_EC_COMPRESSED);
        assert(T_len == 33);

        if (!fill_random(bob_seckey, sizeof(bob_seckey))) {
            std::cout << "Failed to generate randomness\n";
            return 1;
        }

        if (!secp256k1_keypair_create(ctx, &bob_keypair, bob_seckey)) {
            std::cout << "Couldn't generate keypair\n";
            return 1;
        }
        return_val = secp256k1_keypair_xonly_pub(ctx, &bob_pubkey, NULL, &bob_keypair);
        assert(return_val);

        return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
        assert(return_val);

        if (!fill_random(auxiliary_rand, sizeof(auxiliary_rand))) {
            std::cout << "Failed to generate randomness\n";
            return 1;
        }

        t1 = high_resolution_clock::now();
        secp256k1_schnorrsig_sign32(ctx, signature, msg_hash, &bob_keypair, auxiliary_rand);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double, std::milli>>(t2 - t1);
        total_time_generate_common_schnorr += time_span.count();

        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_presign(ctx, adaptor_signature, msg_hash, &bob_keypair, T, NULL);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double, std::milli>>(t2 - t1);
        total_time_presign += time_span.count();
        assert(return_val == 1);

        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_extract_t(ctx, T_prime, adaptor_signature, msg_hash, &bob_pubkey);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double, std::milli>>(t2 - t1);
        total_time_extract_t += time_span.count();
        assert(return_val == 1);
        assert(memcmp(T, T_prime, sizeof(T)) == 0);

        return_val = secp256k1_schnorr_adaptor_adapt(ctx, signature, adaptor_signature, t);
        assert(return_val == 1);

        is_signature_valid = secp256k1_schnorrsig_verify(ctx, signature, msg_hash, 32, &bob_pubkey);
        assert(is_signature_valid);

        t1 = high_resolution_clock::now();
        return_val = secp256k1_schnorr_adaptor_extract_adaptor(ctx, t_prime, adaptor_signature, signature);
        t2 = high_resolution_clock::now();
        time_span = duration_cast<duration<double, std::milli>>(t2 - t1);
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
    std::cout << "Total time for generating common schnorr signature: " << total_time_generate_common_schnorr << " ms" << std::endl;
    std::cout << "Success!\n";

    return 0;
}
int ecdsa_adaptor_benchmark(){
    unsigned char msg[32] = "Hello World";
    unsigned char bob_seckey[32];
    unsigned char alice_seckey[32];
    unsigned char adaptor_sig[162];
    secp256k1_pubkey enckey;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    unsigned char deckey32[32];
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int num_samples = 1000;

    double total_encrypt_time = 0;
    double total_verify_time = 0;
    double total_decrypt_time = 0;
    double total_recover_time = 0;
    double total_time_generate_common_ecdsa = 0;

    for (int i = 0; i < num_samples; i++) {
        if (!fill_random(bob_seckey, sizeof(bob_seckey)) || !fill_random(alice_seckey, sizeof(alice_seckey))) {
            std::cout << "Failed to generate randomness\n";
            return 1;
        }

        if (!secp256k1_ec_pubkey_create(ctx, &enckey, bob_seckey) || !secp256k1_ec_pubkey_create(ctx, &pubkey, alice_seckey)) {
            std::cout << "Couldn't generate keys\n";
            return 1;
        }

        auto start = std::chrono::high_resolution_clock::now();
        int return_val = secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, alice_seckey, &enckey, msg, secp256k1_nonce_function_ecdsa_adaptor, NULL);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> diff = end - start;
        total_encrypt_time += diff.count();

        if (return_val != 1) {
            std::cout << "Failed to generate ECDSA adaptor signature\n";
            return 1;
        }

        start = std::chrono::high_resolution_clock::now();
        return_val = secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig, &pubkey, msg, &enckey);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        total_verify_time += diff.count();

        if (return_val != 1) {
            std::cout << "Failed to verify ECDSA adaptor signature\n";
            return 1;
        }

        start = std::chrono::high_resolution_clock::now();
        return_val = secp256k1_ecdsa_adaptor_decrypt(ctx, &sig, bob_seckey, adaptor_sig);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        total_decrypt_time += diff.count();

        if (return_val != 1) {
            std::cout << "Failed to decrypt ECDSA adaptor signature\n";
            return 1;
        }

        start = std::chrono::high_resolution_clock::now();
        return_val = secp256k1_ecdsa_adaptor_recover(ctx, deckey32, &sig, adaptor_sig, &enckey);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        total_recover_time += diff.count();
        start = std::chrono::high_resolution_clock::now();
        secp256k1_ecdsa_sign(ctx, &sig, msg, deckey32, NULL, NULL);
        end = std::chrono::high_resolution_clock::now();
        diff = end - start;
        total_time_generate_common_ecdsa += diff.count();
        
        if (return_val != 1) {
            std::cout << "Failed to recover decryption key\n";
            return 1;
        }
    }

    std::cout << "Total time for secp256k1_ecdsa_adaptor_encrypt: " << total_encrypt_time << " ms\n";
    std::cout << "Average time for secp256k1_ecdsa_adaptor_encrypt: " << total_encrypt_time / num_samples << " ms\n";
    std::cout << "Total time for secp256k1_ecdsa_adaptor_verify: " << total_verify_time << " ms\n";
    std::cout << "Average time for secp256k1_ecdsa_adaptor_verify: " << total_verify_time / num_samples << " ms\n";
    std::cout << "Total time for secp256k1_ecdsa_adaptor_decrypt: " << total_decrypt_time << " ms\n";
    std::cout << "Average time for secp256k1_ecdsa_adaptor_decrypt: " << total_decrypt_time / num_samples << " ms\n";
    std::cout << "Total time for secp256k1_ecdsa_adaptor_recover: " << total_recover_time << " ms\n";
    std::cout << "Average time for secp256k1_ecdsa_adaptor_recover: " << total_recover_time / num_samples << " ms\n";
    std::cout << "Total time for generating common ecdsa signature: " << total_time_generate_common_ecdsa << " ms\n";
}
int main(void) {

    ecdsa_adaptor_benchmark();
    schnorr_adaptor_benchmark();

    return 0;
}
