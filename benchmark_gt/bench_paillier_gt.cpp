#include <gmpxx.h>
extern "C" {
#include "libpaillier/paillier.h"
}
#include <vector>
#include <memory>
#include <functional>
#include <iostream>
#include <cassert>
#include <cmath>
#include "Timer.hpp"
#include "network.hpp"
#if ENABLE_DEBUG
#define DEBUG(m) std::cerr << m << std::endl
#else
#define DEBUG(m)
#endif

#define SETUPTIMER(id) \
    auto __start__##id = Clock::now();\
    auto   __end__##id = Clock::now();
#define START_TIMER(id) \
    __start__##id = Clock::now();
#define COUNT_AS_MSECOND(id, t) \
    __end__##id = Clock::now(); \
    t.push_back(time_as_millsecond(__end__##id - __start__##id));

using ctxt_deleter_t = std::function<void(paillier_ciphertext_t *)>;
using Ctxt = std::unique_ptr<paillier_ciphertext_t,
                             ctxt_deleter_t>;
using PK = paillier_pubkey_t;
using SK = paillier_prvkey_t;
constexpr inline size_t BIT_TO_BYTE(size_t bits) { return bits >> 3; }
constexpr inline size_t BYTE_TO_BIT(size_t bytes) { return bytes << 3; }
namespace bench_gt {
    long keylen = 1024;
    long bitlen = 12;
    long trial = 100;
    long warmup = 10;
}

void init_rand( gmp_randstate_t rand, paillier_get_rand_t get_rand, int bytes )
{
	void* buf;
	mpz_t s;

	buf = malloc(bytes);
	get_rand(buf, bytes);

	gmp_randinit_default(rand);
	mpz_init(s);
	mpz_import(s, bytes, 1, 1, 0, 0, buf);
	gmp_randseed(rand, s);
	mpz_clear(s);

	free(buf);
}

void deleter(paillier_ciphertext_t *raw) {
    if (raw)
        paillier_freeciphertext(raw);
}

Ctxt add(PK *pk, const Ctxt &c, long v) {
    auto randomness = paillier_get_rand_devurandom;
    auto raw_ptr = paillier_create_enc_zero();
    Ctxt ret(raw_ptr, deleter);
    {
        auto enc_v = paillier_create_enc_zero();
        auto V = paillier_plaintext_from_ui(v);
        paillier_enc(enc_v, pk, V, randomness);
        paillier_mul(pk, ret.get(), c.get(), enc_v);
        paillier_freeplaintext(V);
        deleter(enc_v);
    }
    return std::move(ret);
}

Ctxt add(PK *pk, const Ctxt &c, const Ctxt &b) {
    auto raw_ptr = paillier_create_enc_zero();
    Ctxt ret(raw_ptr, deleter);
    paillier_mul(pk, ret.get(), c.get(), b.get());
    return std::move(ret);
}

Ctxt multiply(PK *pk, const Ctxt &c, paillier_plaintext_t *v) {
    auto raw_ptr = paillier_create_enc_zero();
    Ctxt ret(raw_ptr, deleter);
    paillier_exp(pk, ret.get(), c.get(), v);
    return ret;
}

Ctxt negate(PK *pk, const Ctxt &c) {
    auto raw_ptr = paillier_create_enc_zero();
    Ctxt ret(raw_ptr, deleter);
    mpz_invert(raw_ptr->c, c->c, pk->n_squared);
    return std::move(ret);
}

Ctxt XOR(PK *pk, const Ctxt &c, long b) {
    if (b == 0)
        return add(pk, c, 0);
    else
        return add(pk, negate(pk, c), b);
}

std::vector<Ctxt> encrypt_bits(PK *pk,
                               uint32_t m, uint32_t bitlen)
{
    auto randomness = paillier_get_rand_devurandom;
    std::vector<Ctxt> ctxts;
    paillier_plaintext_t plain;
    mpz_init(plain.m);
    for (uint32_t i = 0; i < bitlen; i++) {
        auto raw_ctx = paillier_create_enc_zero();
        Ctxt c(raw_ctx, deleter);
        ctxts.push_back(std::move(c));
        long b = (m >> (bitlen - i - 1)) & 1;
        mpz_init_set_ui(plain.m, b);
        paillier_enc(ctxts[i].get(), pk, &plain, randomness);
    }
    return ctxts;
}

std::vector<Ctxt> GT(PK *pk,
                     std::vector<Ctxt> const& enc_bits,
                     uint32_t y,
                     long binder_bit,
                     uint32_t bits) {
    assert(binder_bit == 0 || binder_bit == 1);
    assert(enc_bits.size() == bits);
    auto rand_gen = paillier_get_rand_devurandom;
    auto rnd = paillier_plaintext_from_ui(0);
    gmp_randstate_t gmp_rand;
    init_rand(gmp_rand, rand_gen, pk->bits / 8 + 1);

    std::vector<Ctxt> ret;
    auto three = paillier_plaintext_from_ui(3);
    Ctxt accum(paillier_create_enc_zero(), deleter);
    long binder = 1 - 2 * binder_bit;
    for (uint32_t i = 0; i < bits; i++) {
        long ybit = (y >> (bits - i - 1)) & 1;
        auto tmp = add(pk, enc_bits[i], binder - ybit); // xi - yi + 1 or xi - yi
        auto xr = XOR(pk, enc_bits[i], ybit); // xi ^ yi
        xr = multiply(pk, xr, three);

        if (i > 0) {
            tmp = add(pk, tmp, accum);
        }
        accum = add(pk, xr, accum);
        do {
            mpz_urandomb(rnd->m, gmp_rand, pk->bits);
        } while (mpz_cmp_ui(rnd->m, 0) == 0);
        tmp = multiply(pk, tmp, rnd);
        ret.push_back(std::move(tmp));
    }
    std::random_shuffle(ret.begin(), ret.end());
    paillier_freeplaintext(rnd);
    paillier_freeplaintext(three);
    return ret;
}

long decrypt_gt(const std::vector<Ctxt> &enc_bits,
                PK *pk, SK *sk) {
    paillier_plaintext_t *plain = paillier_plaintext_from_ui(0);
    long ret = 0;
    for (auto const &eb : enc_bits) {
        paillier_dec(plain, pk, sk, eb.get());
        long b = mpz_get_ui(plain->m);
        if (b == 0)
            ret = 1;
    }
    return ret;
}

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
    std_dev = std::sqrt(std_dev) / (sze - ignore - 1);
    return {mean, std_dev};
}

void send_mpz(const mpz_t v,
              std::vector<uint32_t> &buf,
              tcp::iostream &conn)
{
    size_t count = 0;
    mpz_export((void *)buf.data(), &count,
               1, sizeof(char), 0, 0, v);
    size_t bytes = buf.size() << 2;
    if (count != bytes)
        DEBUG("buffer size " << bytes << " but get " << count);
    send_big_int(buf, conn);
}

void receive_mpz(mpz_t v,
                 std::vector<uint32_t> &buf,
                 tcp::iostream &conn)
{
    receive_big_int(buf, conn);
    long bytes = BIT_TO_BYTE(buf.size() << 5);
    mpz_import(v, bytes, 1, sizeof(char), 0, 0, (void *)buf.data());
}

void send_pk(const PK *pk, tcp::iostream &conn)
{
    if (!pk) return;
    conn << static_cast<int32_t>(pk->bits) << '\n';
    std::vector<uint32_t> buf(pk->bits >> 5);
    send_mpz(pk->n, buf, conn);
}

void receive_pk(PK *pk, tcp::iostream &conn)
{
    if (!pk) return;
    int32_t bits;
    conn >> bits;
    pk->bits = bits;
    mpz_init(pk->n);
    mpz_init(pk->n_squared);
    mpz_init(pk->n_plusone);
    std::vector<uint32_t> buf(bits >> 5);
    receive_mpz(pk->n, buf, conn);
    mpz_mul(pk->n_squared, pk->n, pk->n);
    mpz_add_ui(pk->n_plusone, pk->n, 1);
}

void send_ctxts(std::vector<Ctxt> const& ctx,
               std::vector<uint32_t> &buf,
               tcp::iostream &conn)
{
    conn << static_cast<int32_t>(ctx.size()) << '\n';
    for (const auto &c : ctx) {
        send_mpz(c->c, buf, conn);
    }
}

void receive_ctxts(std::vector<Ctxt> &ctx,
                   std::vector<uint32_t> &buf,
                   tcp::iostream &conn)
{
    int32_t num_ctxt;
    conn >> num_ctxt;
    ctx.clear();
    ctx.reserve(num_ctxt);
    for (int32_t i = 0; i < num_ctxt; i++) {
        auto raw_ptr = paillier_create_enc_zero();
        ctx.emplace_back(raw_ptr, deleter);
        receive_mpz(ctx[i]->c, buf, conn);
    }
}

void play_server(tcp::iostream &conn)
{
    PK *pk = new PK();
    receive_pk(pk, conn);
    std::vector<uint32_t> buf((pk->bits << 1) >> 5);
    std::vector<double> times[4];
    SETUPTIMER(0);
    SETUPTIMER(1);
    for (long _i = 0; _i < bench_gt::trial; _i++) {
        START_TIMER(1);
        std::vector<Ctxt> ctxts;
        receive_ctxts(ctxts, buf, conn);

        const long mask = (1 << (bench_gt::bitlen - 1)) - 1;
        long a = std::rand() % mask;
        START_TIMER(0);
        long binder_bit = std::rand() & 1;
        auto ret = GT(pk, ctxts, a, binder_bit, bench_gt::bitlen);
        COUNT_AS_MSECOND(0, times[0]);
        DEBUG("a = " << a);
        START_TIMER(0);
        send_ctxts(ret, buf, conn);
        COUNT_AS_MSECOND(0, times[1]);

        std::vector<Ctxt> reencrypted;
        receive_ctxts(reencrypted, buf, conn);
        assert(reencrypted.size() == 1);

        START_TIMER(0);
        Ctxt final = XOR(pk, reencrypted[0], binder_bit);
        COUNT_AS_MSECOND(0, times[2]);

        COUNT_AS_MSECOND(1, times[3]);
    }
    std::cout << "eval network XOR end-2-end" << std::endl;
    for (auto &time : times) {
        auto ms = mean_std(time, bench_gt::warmup);
        printf("%.3f %.3f ", ms.first, ms.second);
    }
    std::cout << std::endl;

    delete pk;
}

void play_client(tcp::iostream &conn)
{
    const long mask = (1 << (bench_gt::bitlen - 1)) - 1;
    auto rnd_gen = paillier_get_rand_devurandom;
    PK *pk;
    SK *sk;
    paillier_keygen(bench_gt::keylen, &pk, &sk, rnd_gen);
    send_pk(pk, conn);
    SETUPTIMER(0);
    SETUPTIMER(1);
    std::vector<double> times[5];
    for (long _i = 0; _i < bench_gt::trial; _i++) {
        START_TIMER(1); // end-to-end time
        long b = std::rand() % mask;
        DEBUG("b = " << b);
        START_TIMER(0);
        auto enc_bits = encrypt_bits(pk, b, bench_gt::bitlen);
        COUNT_AS_MSECOND(0, times[0]);

        std::vector<uint32_t> buf((pk->bits << 1) >> 5);
        START_TIMER(0);
        send_ctxts(enc_bits, buf, conn);
        COUNT_AS_MSECOND(0, times[1]);
        DEBUG("waiting result from server");

        std::vector<Ctxt> result;
        receive_ctxts(result, buf, conn);

        START_TIMER(0);
        long gt= decrypt_gt(result, pk, sk);
        std::vector<Ctxt> enc_gt = encrypt_bits(pk, gt, 1);
        COUNT_AS_MSECOND(0, times[2]);

        START_TIMER(0);
        send_ctxts(enc_gt, buf, conn);
        COUNT_AS_MSECOND(0, times[3]);
        DEBUG("GT " << gt);

        COUNT_AS_MSECOND(1, times[4]);
    }
    std::cout << "enc network dec network end-2-end" << std::endl;
    for (auto &time : times) {
        auto ms = mean_std(time, bench_gt::warmup);
        printf("%.3f %.3f ", ms.first, ms.second);
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[]) {
    long r = 0;
    std::srand(std::time(0));
    if (argc > 1)
        r = std::stol(argv[1]);
    switch(r) {
    case 0:
        std::cout << "waiting for client..." << std::endl;
        run_server(play_server);
        break;
    case 1:
        std::cout << "connect to server..." << std::endl;
        run_client(play_client);
        break;
    }
    return 0;
}

#if 0
int main(int argc, char *argv[]) {
    auto randomness = paillier_get_rand_devurandom;
    int bitlen = 1024;
    if (argc > 1)
        bitlen = std::atoi(argv[1]);
    PK *pk;
    SK *sk;
    paillier_keygen(bitlen, &pk, &sk, randomness);
    std::vector<double> times[3];
    long delta = 12;
    long mask = (1 << (delta - 1)) - 1;
    std::srand(std::time(0));

    for (long i = 0; i < 50; i++) {
        long a = rand() & mask;
        long b = rand() & mask;
        auto start = Clock::now();
        auto enc_bits = encrypt_bits(pk, a, delta);
        auto end = Clock::now();
        times[0].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        auto gt_res = GT(pk, enc_bits, b, delta);
        end = Clock::now();
        times[1].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        long ret = decrypt_gt(gt_res, pk, sk);
        end = Clock::now();
        if ((a < b) != ret)
            std::cout << "Wrong answer\n" << std::endl;
        times[2].push_back(time_as_millsecond(end - start));
    }

    for (auto &tt : times) {
        auto md = mean_std(tt, 0);
        printf("%.3f %.4f ", md.first, md.second);
    }
    return 0;
}
#endif
