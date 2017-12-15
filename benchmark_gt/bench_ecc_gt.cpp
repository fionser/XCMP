#include <cybozu/random_generator.hpp>
#ifdef MCL_DONT_USE_OPENSSL
#include <cybozu/sha1.hpp>
#else
#include <cybozu/crypto.hpp>
#endif
#include <mcl/fp.hpp>
#include <mcl/ecparam.hpp>
#include <mcl/elgamal.hpp>

#include <chrono>
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

struct TagZn;
typedef mcl::FpT<> Fp;
typedef mcl::FpT<TagZn> Zn;
typedef mcl::EcT<Fp> Ec;
typedef mcl::ElgamalT<Ec, Zn> ElgamalEc;

namespace bench_gt {
    const mcl::EcParam& para = mcl::ecparam::secp160k1;
    long bitlen = 12;
    //const mcl::EcParam& para = mcl::ecparam::secp256k1;
    //long bitlen = 13;
    long trial = 100;
    long warmup = 10;
}

cybozu::RandomGenerator rg;

std::vector<ElgamalEc::CipherText> 
encrypt_bits(ElgamalEc::PublicKey const&pk, 
             uint32_t m,
             uint32_t bits) {
    std::vector<ElgamalEc::CipherText> ctxts(bits);
    for (uint32_t i = 0; i < bits; i++) {
        int b = (m >> i) & 1;
        pk.enc(ctxts[i], b, rg);
    }
    return ctxts;
}

int decrypt_gt(ElgamalEc::PrivateKey const& sk,
               std::vector<ElgamalEc::CipherText> const& ctxts) {
    for (const auto& ct: ctxts) {
        if (sk.isZeroMessage(ct))
            return 1;
    }
    return 0;
}

ElgamalEc::CipherText XOR(ElgamalEc::PublicKey const& pk,
                          ElgamalEc::CipherText const& ct,
                          int y) {
    ElgamalEc::CipherText c(ct);
    if (y == 1) {
        c.neg();
        pk.add(c, 1);
    } else {
        pk.rerandomize(c, rg);
    }
    return c;
}

std::vector<ElgamalEc::CipherText> GT(ElgamalEc::PublicKey const& pk,
                                      std::vector<ElgamalEc::CipherText> const& enc_x,
                                      int y, 
                                      int binder_bit,
                                      uint32_t bits) {
    assert(bits == enc_x.size());
    assert(binder_bit == 0 || binder_bit == 1);
    ElgamalEc::CipherText z, accum;
    pk.enc(accum, 0, rg);
    std::vector<ElgamalEc::CipherText> ret;
    long binder = 1 - 2* binder_bit;
    for (size_t i = 0; i < bits; i++) {
        int ybit = (y >> (bits - i - 1)) & 1;
        z = enc_x[i];
        pk.add(z, binder - ybit);
        auto _xor = XOR(pk, enc_x[i], ybit);
        _xor.mul(3);
        if (i > 0) {
            z.add(accum);
        }
        accum.add(_xor);
        ret.push_back(z);
    }
    std::random_shuffle(ret.begin(), ret.end());
    return ret;
}

void send_ctxts(std::vector<ElgamalEc::CipherText> const& ctxts,
                tcp::iostream &conn)
{
    int32_t num = static_cast<int32_t>(ctxts.size());
    conn << num << '\n';
    for (const auto &ctx : ctxts)
        conn << ctx << '\n';
}

void receive_ctxts(std::vector<ElgamalEc::CipherText> &ctxts,
                   tcp::iostream &conn)
{
    int32_t num;
    conn >> num;
    ctxts.resize(num);
    for (int32_t i = 0; i < num; i++)
        conn >> ctxts[i];
}

void play_server(tcp::iostream &conn)
{
    const long maximum = (1 << (bench_gt::bitlen - 1)) - 1;
    ElgamalEc::PublicKey pub;
    conn >> pub;
    SETUPTIMER(0);
    SETUPTIMER(1);
    std::vector<double> times[3];
    for (long _i = 0; _i < bench_gt::trial; _i++) {
        START_TIMER(0);
        std::vector<ElgamalEc::CipherText> ctxts;
        receive_ctxts(ctxts, conn);
        assert(ctxts.size() == bench_gt::bitlen);
        long server_input = std::rand() % maximum;
        long binder_bit = std::rand() & 1;
        START_TIMER(1);
        auto gt_result = GT(pub, ctxts, server_input, 
                            binder_bit, bench_gt::bitlen);
        COUNT_AS_MSECOND(1, times[0]);
        send_ctxts(gt_result, conn);

        std::vector<ElgamalEc::CipherText> reencrypted;
        receive_ctxts(reencrypted, conn);
        assert(reencrypted.size() == 1);
        START_TIMER(1);
        auto final = XOR(pub, reencrypted[0], binder_bit);
        COUNT_AS_MSECOND(1, times[1]);
        COUNT_AS_MSECOND(0, times[2]);
    }
    std::cout << "enc dec-reencrypt end-2-end" << std::endl;
    for (auto &time : times) {
        auto ms = mean_std(time, bench_gt::warmup);
        printf("%.3f %.3f ", ms.first, ms.second);
    }
}

void play_client(tcp::iostream &conn)
{
	const Fp x0(bench_gt::para.gx);
	const Fp y0(bench_gt::para.gy);
	const Ec P(x0, y0);
	const size_t bitSize = Zn::getBitSize();
    const long maximum = (1 << (bench_gt::bitlen - 1)) - 1;
	ElgamalEc::PrivateKey prv;
	prv.init(P, bitSize, rg);
	prv.setCache(0, 60000);
	const ElgamalEc::PublicKey& pub = prv.getPublicKey();
    conn << pub << '\n';
    long client_input = std::rand() % maximum; 

    SETUPTIMER(0);
    SETUPTIMER(1);
    std::vector<double> times[3];
    for (long _i = 0; _i < bench_gt::trial; _i++)  {
        START_TIMER(0);
        START_TIMER(1);
        auto enc_bits = encrypt_bits(pub, client_input, bench_gt::bitlen);
        COUNT_AS_MSECOND(1, times[0]);
        send_ctxts(enc_bits, conn);

        std::vector<ElgamalEc::CipherText> gt_result;
        receive_ctxts(gt_result, conn);
        START_TIMER(1);
        int s = decrypt_gt(prv, gt_result);
        gt_result.resize(1);
        pub.enc(gt_result[0], s, rg);
        COUNT_AS_MSECOND(1, times[1]);
        send_ctxts(gt_result, conn);
        COUNT_AS_MSECOND(0, times[2]);
    }
    std::cout << "enc dec-reencrypt end-2-end" << std::endl;
    for (auto &time : times) {
        auto ms = mean_std(time, bench_gt::warmup);
        printf("%.3f %.3f ", ms.first, ms.second);
    }
}

void init()
{
	Fp::init(bench_gt::para.p);
	Zn::init(bench_gt::para.n);
	Ec::init(bench_gt::para.a, bench_gt::para.b);

    std::srand(std::time(0));
}


int main(int argc, char *argv[]) {
    long r = 0;
    if (argc > 1)
        r = std::stol(argv[1]);

    switch(r) {
    case 0:
        init();
        std::cout << "waiting for client..." << std::endl;
        run_server(play_server);
        break;
    case 1:
        init();
        std::cout << "connect to server..." << std::endl;
        run_client(play_client);
        break;
    }
    return 0;
}

#if 0
int main(int argc, char *argv[]) {
	Fp::init(para.p);
	Zn::init(para.n);
	Ec::init(para.a, para.b);
	const Fp x0(para.gx);
	const Fp y0(para.gy);
	const size_t bitSize = Zn::getBitSize();
    std::cout << "bitSize " << bitSize <<"\n";
	const Ec P(x0, y0);
	/*
		Zn = <P>
	*/
	ElgamalEc::PrivateKey prv;
	prv.init(P, bitSize, rg);
	prv.setCache(0, 60000);
	const ElgamalEc::PublicKey& pub = prv.getPublicKey();
    std::vector<double> times[3];
    for (int i = 0; i < 1000; i++) {
        auto start = Clock::now();
        auto enc_bits = encrypt_bits(pub, 11, 13);
        auto end = Clock::now();
        times[0].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        auto gt_res = GT(pub, enc_bits, 10, 13);
        end = Clock::now();
        times[1].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        int s = decrypt_gt(prv, gt_res);
        end = Clock::now();
        times[2].push_back(time_as_millsecond(end - start));
    }

    for (auto &tt : times) {
        auto ms = mean_std(tt, 50);
        std::cout << ms.first << " " << ms.second << " ";
    }
    std::cout << std::endl;
    return 0;
}
#endif
