#include <iostream>
#include <vector>
#include <string>

#include "seal/seal.h"
#include <NTL/ZZ.h>
#include <chrono>

using std::chrono::duration_cast;
typedef std::chrono::nanoseconds Time_t;
typedef std::chrono::high_resolution_clock Clock;
double time_as_second(const Time_t &t) { return t.count() / 1.0e9; }
double time_as_millsecond(const Time_t &t) { return t.count() / 1.0e6; }
std::pair<double, double> mean_std(std::vector<double> const& times, long ignore) {
    long sze = times.size();
    double mean = 0.;
    for (long i = ignore; i < sze; i++) {
        mean += times[i];
    }
    mean /= (sze - ignore);
    double std_dev = 0.;
    for (long i = ignore; i < sze; i++) {
        std_dev += (times[i] - mean) * (times[i] - mean);
    }
    std_dev = std::sqrt(std_dev / (sze - ignore - 1));
    return {mean, std_dev};
}


using namespace seal;

void run_private_comparison();

int main()
{
    run_private_comparison();
    return 0;
}

void encrypt_on_degree(Ciphertext &c,
                       long v,
                       Encryptor &encr)

{
    std::string str = "1x^" + std::to_string(v);
    Plaintext plain(str);
    encr.encrypt(plain, c);
}

Plaintext create_test_vector(long m, uint64_t coeff = 1) {
    Plaintext poly(m);
    for (long i = m - 1; i >= 0; i--) {
        poly[i] = coeff;
    }
    return poly;
}

struct CompareArgs {
    Plaintext test_v;
    int64_t mu0, mu1;
    uint64_t half;
};

CompareArgs create_compare_args(uint64_t gt,
                                uint64_t otherwise,
                                SEALContext const& context)
{
    uint64_t p = context.plain_modulus().value();
    CompareArgs args;
    args.mu0 = gt;
    args.mu1 = otherwise;
    uint64_t inv = NTL::InvMod(2, p);
    args.half = ((gt + otherwise) * inv) % p; // (mu0 + mu1)/2
    uint64_t coeff;
    if (otherwise > args.half) {
        coeff = otherwise - args.half;
    } else {
        coeff = p + otherwise - args.half;
    }
    long m = context.poly_modulus().coeff_count() - 1;
    args.test_v = create_test_vector(m, coeff);
    return args;
}

void random_poly(Plaintext &poly,
                 long degree,
                 uint64_t modulus) {
    poly.resize(degree);
    for (long i = degree - 1; i >= 0; i--) {
         poly[i] = NTL::RandomBnd(modulus);
    }
}

Ciphertext compare(Ciphertext const& c,
                   long b,
                   CompareArgs const& args,
                   SEALContext const& context,
                   Evaluator &evl)
{
    long m = context.poly_modulus().coeff_count() - 1;
    uint64_t p = context.plain_modulus().value();
    std::string hex;
    auto tv(args.test_v);

    // negate the coefficient from X^{m - b - 1} to X^{m-1}
    for (long i = 1; i <= b; i++)
        tv[m - i] = p - tv[m - i];

    Ciphertext ret(c);
    evl.multiply_plain(ret, tv); //X^{a-b} * test_v

    random_poly(tv, m, p);
    tv[0] = args.half;
    evl.add_plain(ret, tv);
    return ret;
}

/// NOTE. SEAL does not support Frobinious map yet.
/// So this function just for benchmarking
Ciphertext compare(Ciphertext const& a,
                   Ciphertext const& b,
                   CompareArgs const& args,
                   SEALContext const& context,
                   Evaluator &evl)
{
    long m = context.poly_modulus().coeff_count() - 1;
    uint64_t p = context.plain_modulus().value();

    auto tv(args.test_v);
    /// Should include a step to negate X^b to X^{-b}
    Ciphertext ret(a);
    evl.multiply(ret, b);
    evl.multiply_plain(ret, tv); //X^{a-b} * test_v

    random_poly(tv, m, p);
    tv[0] = args.half;
    evl.add_plain(ret, tv);
    return ret;
}

void run_private_comparison()
{
    long m = 4096;
    long p = 1013;
    EncryptionParameters parms;
    parms.set_poly_modulus("1x^" + std::to_string(m) + " + 1");
    parms.set_coeff_modulus(coeff_modulus_128(m));
    parms.set_plain_modulus(p); // can be non prime
    SEALContext context(parms);

    IntegerEncoder encoder(context.plain_modulus());

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    auto gt_args = create_compare_args(1, 0, context);

    Plaintext dec;
    Ciphertext ctx_a, ctx_b;
    std::vector<double> times[3];
    for (int i = 0; i < 1000; i++) {
        long a = NTL::RandomBnd(m);
        long b = NTL::RandomBnd(m);
        uint64_t gt = a > b;

        auto start = Clock::now();
        encrypt_on_degree(ctx_a, a, encryptor);
        encrypt_on_degree(ctx_b, b, encryptor);
        auto end = Clock::now();
        times[0].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        auto ret = compare(ctx_a, ctx_b, gt_args, context, evaluator);
        end = Clock::now();
        times[1].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        decryptor.decrypt(ret, dec);
        end = Clock::now();
        times[2].push_back(time_as_millsecond(end - start));
        if (gt != dec[0])
            std::cerr << "Error:" << gt << "!= " << dec[0] << std::endl;
    }

    for (auto &tt : times) {
        auto ms = mean_std(tt, 100);
        std::cout << ms.first << " "  << ms.second << " ";
    }
    std::cout << std::endl;
}
