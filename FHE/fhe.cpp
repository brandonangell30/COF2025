#include <iostream>
#include "Users/brandonangell/SEAL/native/src/seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    // Encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(PlainModulus::Batching(8192, 20));
    SEALContext context(parms);

    // Key generation
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    // Encrypt the value x = a (a = 3 for example)
    int a = 3;
    Plaintext x_plain(to_string(a));
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    // Polynomial coefficients: f(x) = ax^2 + bx + c
    int coeff_a = 2, coeff_b = 3, coeff_c = 5;

    // Compute x^2, multiply by a, then multiply x by b, and add c
    Ciphertext x_squared, ax2, bx, result;
    evaluator.square(x_encrypted, x_squared);          // x^2
    evaluator.multiply_plain(x_squared, to_string(coeff_a), ax2); // a * x^2
    evaluator.multiply_plain(x_encrypted, to_string(coeff_b), bx); // b * x
    evaluator.add(ax2, bx, result); // a * x^2 + b * x
    evaluator.add_plain_inplace(result, to_string(coeff_c)); // + c

    // Decrypt and print the result
    Plaintext decrypted_result;
    decryptor.decrypt(result, decrypted_result);
    cout << "Decrypted result: " << decrypted_result.to_string() << endl;

    return 0;
}
