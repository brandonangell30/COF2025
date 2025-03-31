#include <iostream>
#include "seal/seal.h"
using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up the encryption parameters
    // Using BFV with a large enough plain modulus
    EncryptionParameters params(scheme_type::bfv);
    params.set_poly_modulus_degree(4096);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
    // Using a plain modulus much larger than our expected result
    params.set_plain_modulus(65537);  // A prime number larger than any expected result
    
    SEALContext context(params);
    
    // Step 2: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Step 3: Set up encryption/decryption tools
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 4: Set up a batch encoder
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    
    // Step 5: Define our polynomial f(x) = 2x² + 3x + 1
    uint64_t input_value = 5;  // The value x = 5
    uint64_t a = 2;  // Coefficient of x²
    uint64_t b = 3;  // Coefficient of x
    uint64_t c = 1;  // Constant term
    
    cout << "Evaluating f(x) = " << a << "x² + " << b << "x + " << c << " at x = " << input_value << endl;
    
    // Step 6: Prepare input for batch encoding
    vector<uint64_t> pod_input(slot_count, 0);
    pod_input[0] = input_value;
    
    // Step 7: Encode and encrypt
    Plaintext plain_input;
    encoder.encode(pod_input, plain_input);
    Ciphertext encrypted_input;
    encryptor.encrypt(plain_input, encrypted_input);
    
    // Step 8: Compute x²
    Ciphertext encrypted_squared;
    evaluator.square(encrypted_input, encrypted_squared);
    evaluator.relinearize_inplace(encrypted_squared, relin_keys);
    
    // Step 9: Compute ax²
    Plaintext plain_a;
    vector<uint64_t> pod_a(slot_count, 0);
    pod_a[0] = a;
    encoder.encode(pod_a, plain_a);
    Ciphertext encrypted_ax2;
    evaluator.multiply_plain(encrypted_squared, plain_a, encrypted_ax2);
    
    // Step 10: Compute bx
    Plaintext plain_b;
    vector<uint64_t> pod_b(slot_count, 0);
    pod_b[0] = b;
    encoder.encode(pod_b, plain_b);
    Ciphertext encrypted_bx;
    evaluator.multiply_plain(encrypted_input, plain_b, encrypted_bx);
    
    // Step 11: Compute ax² + bx
    Ciphertext encrypted_ax2_plus_bx;
    evaluator.add(encrypted_ax2, encrypted_bx, encrypted_ax2_plus_bx);
    
    // Step 12: Compute ax² + bx + c
    Plaintext plain_c;
    vector<uint64_t> pod_c(slot_count, 0);
    pod_c[0] = c;
    encoder.encode(pod_c, plain_c);
    Ciphertext encrypted_result;
    evaluator.add_plain(encrypted_ax2_plus_bx, plain_c, encrypted_result);
    
    // Step 13: Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    
    // Step 14: Decode the result
    vector<uint64_t> result;
    encoder.decode(plain_result, result);
    
    cout << "Encrypted computation result: f(" << input_value << ") = " << result[0] << endl;
    
    // Verify with direct computation
    uint64_t direct_result = a * input_value * input_value + b * input_value + c;
    cout << "Direct computation result: f(" << input_value << ") = " << direct_result << endl;
    
    return 0;
}