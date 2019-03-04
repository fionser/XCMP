#include <seal/seal.h>
using namespace seal;

struct ComparableCipher {
  std::array<seal::Ciphertext *, 2> dat_;
  
  ComparableCipher() : dat_({nullptr, nullptr}) {
    dat_[0] = new seal::Ciphertext();
    dat_[1] = new seal::Ciphertext();
  }

  ~ComparableCipher() {
    for (int i : {0, 1}) {
      if (dat_[i]) {
        delete dat_[i];
      }
    }
  }
};

void encrypt_comparable_int(uint32_t v,
                            std::shared_ptr<seal::SEALContext> context,
                            seal::Encryptor &encryptor,
                            ComparableCipher &out)
{
  const long d = context->context_data()->parms().poly_modulus_degree();
  if (v >= d * d) {
    std::cerr << "out of range error: the maximum value to encrypt is " << d * d << "\n";
    return;
  }
  // v = v1 * d + v0
  uint32_t v0 = v % d;
  uint32_t v1 = v / d;
  seal::Plaintext plain(d, d);
  plain.set_zero();
  // X^{v0}
  plain.data()[v0] = 1;
  encryptor.encrypt(plain, *(out.dat_[0]));
  // X^{v1}
  plain.data()[v0] = 0;
  plain.data()[v1] = 1;
  encryptor.encrypt(plain, *(out.dat_[1]));
}

// Keep only the constant term (i.e., p0) of the encrypted polynomial p(X).
// Enc(p(X)) --> Enc(p0)
// Complexity: logN galois depth, where N is the parameter in the poly modulus X^N + 1.
void zero_out_non_constant_terms(seal::Ciphertext &ctx,
                                 std::shared_ptr<seal::SEALContext> context,
                                 seal::Evaluator &evaluator,
                                 seal::GaloisKeys& gal_keys)
{
  const auto& parms = context->context_data()->parms();
  const long d = parms.poly_modulus_degree();
  const long n = (long) (std::log2((double) d));
  for (long i = 0; i < n; ++i) {
    Ciphertext tmp{ctx};
    evaluator.apply_galois_inplace(tmp, (d / (1 << i)) + 1, gal_keys);
    evaluator.add_inplace(ctx, tmp);
  }

  Plaintext plain(d, d);
  plain.set_zero();

  uint64_t inv_d;
  util::try_mod_inverse(d, parms.plain_modulus().value(), inv_d);
  plain.data(0)[0] = inv_d;
  evaluator.multiply_plain_inplace(ctx, plain);
}

// The low-level to inequality-test two encrypted integer range in [0, d).
void __neq_ciphers(seal::Ciphertext const& c0, // X^{a}
                   seal::Ciphertext const& c1, // X^{-b}
                   std::shared_ptr<seal::SEALContext> context,
                   seal::Evaluator &evaluator,
                   seal::GaloisKeys& gal_keys,
                   seal::Ciphertext &out)
{
  const auto& parms = context->context_data()->parms();
  const long d = parms.poly_modulus_degree();
  const uint64_t p = parms.plain_modulus().value();

  evaluator.multiply(c0, c1, out); // X^{a - b}

  seal::Plaintext plain(d, d);
  plain.data()[0] = 1; // 1
  evaluator.sub_plain_inplace(out, plain);
  evaluator.negate_inplace(out);
}

// The low-level to compare two encrypted integer range in [0, d).
void __compare_ciphers(seal::Ciphertext const& c0, // X^{a}
                       seal::Ciphertext const& c1, // X^{-b}
                       std::shared_ptr<seal::SEALContext> context,
                       seal::Evaluator &evaluator,
                       seal::GaloisKeys& gal_keys,
                       seal::Ciphertext &out)
{
  const auto& parms = context->context_data()->parms();
  const long d = parms.poly_modulus_degree();
  const uint64_t p = parms.plain_modulus().value();
  // 2^-1 mod p
  uint64_t inv2;
  util::try_mod_inverse(2, p, inv2);
  uint64_t neg_inv_2 = (p - inv2) % p;
  seal::Plaintext plain(d, d);
  for (long i = 0; i < d; ++i)
    plain.data()[i] = neg_inv_2;

  evaluator.multiply(c0, c1, out);
  evaluator.multiply_plain_inplace(out, plain);

  plain.set_zero();
  plain.data()[0] = inv2;
  for (long i = 1; i < d; ++i)
      plain.data()[i] = std::rand() % p;
  evaluator.add_plain_inplace(out, plain);
}

// Compare the encrypted integers range in [0, d^2)
// Return a ciphertext that decrypts a poly p(X) 
// if c0 > c1, then p[0] = 1
//             else p[0] = 0
void compare_ciphers(ComparableCipher const& c0,
                     ComparableCipher const& c1,
                     std::shared_ptr<seal::SEALContext> context,
                     seal::Evaluator &evaluator,
                     seal::RelinKeys &relin_key,
                     seal::GaloisKeys &gal_keys,
                     seal::Ciphertext &out)
{
  const auto& parms = context->context_data()->parms();
  const long d = parms.poly_modulus_degree();

  seal::Ciphertext c1_lo{*c1.dat_[0]};
  seal::Ciphertext c1_hi{*c1.dat_[1]}; 
  // negate the second operand
  evaluator.apply_galois_inplace(c1_lo, 2 * d - 1, gal_keys);
  evaluator.apply_galois_inplace(c1_hi, 2 * d - 1, gal_keys);

  // compare the high and low digits
  seal::Ciphertext cmp_hi, cmp_lo;
  __compare_ciphers(*c0.dat_[0], c1_lo, context, evaluator, gal_keys, cmp_lo);
  __compare_ciphers(*c0.dat_[1], c1_hi, context, evaluator, gal_keys, cmp_hi);
  
  // The domain extend algorithm.
  // 1{c0_hi != c1_hi} * (1{c0_hi > c1_hi} - 1{c0_lo > c1_lo}) + 1{c0_lo > c1_lo}) 
  seal::Ciphertext neq_hi;
  __neq_ciphers(*c0.dat_[1], c1_hi, context, evaluator, gal_keys, neq_hi);
  evaluator.relinearize_inplace(neq_hi, relin_key);
  zero_out_non_constant_terms(neq_hi, context, evaluator, gal_keys);
  
  evaluator.sub_inplace(cmp_hi, cmp_lo);
  evaluator.relinearize_inplace(cmp_hi, relin_key);
  evaluator.multiply(neq_hi, cmp_hi, out);
  evaluator.add_inplace(out, cmp_lo);
  
  evaluator.relinearize_inplace(out, relin_key);
}

int main() {
  EncryptionParameters parms(scheme_type::BFV);
  parms.set_poly_modulus_degree(8192);
  parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
  parms.set_plain_modulus(1013);
  auto context = SEALContext::Create(parms);
  KeyGenerator keygen(context);
  PublicKey public_key = keygen.public_key();
  SecretKey secret_key = keygen.secret_key();

  const long d = parms.poly_modulus_degree();
  const long N = (long) std::log2((double) d);

  auto gal_keys = keygen.galois_keys(30); // two digits
  auto relin_key = keygen.relin_keys(60); // no digit decomposition

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);

  ComparableCipher cc0, cc1;
  for (long i = 0; i < 10; ++i) {
    int v0 = std::rand() % (d*d); // the acceptable range is [0, d * d) where d = 8192
    int v1 = std::rand() % (d*d);
    encrypt_comparable_int(v0, context, encryptor, cc0);
    encrypt_comparable_int(v1, context, encryptor, cc1);

    seal::Ciphertext ans;
    compare_ciphers(cc0, cc1, context, evaluator, relin_key, gal_keys, ans);

    seal::Plaintext plain(d, d);
    plain.set_zero();
    decryptor.decrypt(ans, plain);
    if (v0 > v1) {
      if (plain.data()[0] != 1) {
        std::cout << "v0 > v1 error. want 1 but " << plain.data()[0] << "\n";
        std::cout << (v0 / d) << " + " << (v0 % d) << "\n";
        std::cout << (v1 / d) << " + " << (v1 % d) << "\n";
      }
    } else if (plain.data()[0] != 0) {
      std::cout << "v0 <= v1 error. want 0 but " << plain.data()[0] << "\n";
      std::cout << (v0 / d) << " + " << (v0 % d) << "\n";
      std::cout << (v1 / d) << " + " << (v1 % d) << "\n";
    }
  }
  return 0;
}
