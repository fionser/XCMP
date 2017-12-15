#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<gmpxx.h>
#include <vector>
#include <cmath>
#include "Timer.hpp"
extern "C" {
#include "libgm/gm.h"
}

void generatekey(gm_pubkey_t **pk, 
                 gm_prvkey_t **sk,
                 int bitlen)
{
    gm_keygen(bitlen, pk, sk, gm_get_rand_devurandom);
}

typedef struct Ctxt {
    gm_ciphertext_t **c;
    int lambda;
} Ctxt;

void copy(Ctxt *to, Ctxt *from) {
    for (int i = 0; i < to->lambda; i++) {
        mpz_set(to->c[i]->c, from->c[i]->c);
    }
}

void alloc(Ctxt *ctx, int lambda) {
    ctx->c = (gm_ciphertext_t **) malloc(sizeof (gm_ciphertext_t *) * lambda);
    for (int i = 0; i < lambda; i++) {
        ctx->c[i] = (gm_ciphertext_t *)malloc(sizeof(gm_ciphertext_t));
    }
    ctx->lambda = lambda;
}

void free_ctx(Ctxt *ctx) {
    for (int i = 0; i < ctx->lambda; i++) {
        gm_freeciphertext(ctx->c[i]);
    }
    free(ctx->c);
}

void encrypt(Ctxt *ctx, gm_pubkey_t *pk, int b) {
    for (int i = 0; i < ctx->lambda; i++)
        ctx->c[i] = gm_enc_bit(NULL, pk, b,
                               gm_get_rand_devurandom);
}

int decrypt(gm_prvkey_t *sk, Ctxt *ctx) {
    if (ctx->lambda > 1) {
        for (int i = 0; i < ctx->lambda; i++) {
            int b = gm_dec_bit(sk, ctx->c[i]);
            if (b == 1)
                return 0;
        }
        return 1;
    } else {
        return gm_dec_bit(sk, ctx->c[0]);
    }
}

void randomize(gm_ciphertext_t *out, 
               gm_ciphertext_t*from, 
               gm_pubkey_t *pk) {
    Ctxt zero;
    alloc(&zero, 1);
    encrypt(&zero, pk, 0);
    gm_mul(pk, out, from, zero.c[0]);
    free_ctx(&zero);
}

void NOT(Ctxt *Not, gm_pubkey_t *pk, Ctxt *in) {
    gm_ciphertext_t _pk;
    mpz_init_set(_pk.c, pk->x);
    for (int i = 0; i < in->lambda; i++)
        gm_mul(pk, Not->c[i], in->c[i], &_pk);
    mpz_clear(_pk.c);
}

void XOR(Ctxt *Xor, gm_pubkey_t *pk, Ctxt *ctx, Ctxt *ctx2) {
    for (int i = 0; i < ctx->lambda; i++)
        gm_mul(pk, Xor->c[i], ctx->c[i], ctx2->c[i]);
}

void NXOR(Ctxt *nor, gm_pubkey_t *pk, Ctxt *ctx, Ctxt *ctx2) {
    Ctxt Xor;
    alloc(&Xor, ctx->lambda);
    XOR(&Xor, pk, ctx, ctx2);
    NOT(nor, pk, &Xor);
    free_ctx(&Xor);
}

void extend(Ctxt *extend, gm_pubkey_t *pk, Ctxt *from) {
    if (from->lambda != 1) {
        printf("error for extension\n");
    }

    Ctxt tmp;
    alloc(&tmp, 1);
    for (int i = 0; i < extend->lambda; i++) {
        int b = rand() % 2;
        if (b == 0) {
            NOT(&tmp, pk, from);
            randomize(extend->c[i], tmp.c[0], pk);
        } else {
            extend->c[i] = gm_enc_bit(NULL, pk, 0,
                                      gm_get_rand_devurandom);
        }
    }
}

void extend2(Ctxt *extend, gm_pubkey_t *pk, Ctxt *from) {
    if (from->lambda != 1) {
        printf("error for extension\n");
    }

    Ctxt tmp;
    alloc(&tmp, 1);
    for (int i = 0; i < extend->lambda; i++) {
        int b = rand() % 2;
        if (b == 0) {
            randomize(extend->c[i], from->c[0], pk);
        } else {
            extend->c[i] = gm_enc_bit(NULL, pk, 0,
                                      gm_get_rand_devurandom);
        }
    }
}



void AND(Ctxt *And, gm_pubkey_t *pk, Ctxt *ctx, Ctxt *ctx2) {
    for (int i = 0; i < ctx->lambda; i++) {
        gm_mul(pk, And->c[i], ctx->c[i], ctx2->c[i]);
    }
}

typedef struct EncBits {
    Ctxt **bits;
    int bitlen;
} EncBits;

void allocate(EncBits *eb, int bitlen, int lambda) {
    eb->bits = (Ctxt **) malloc(sizeof (Ctxt *) * bitlen);
    for (int i = 0; i < bitlen; i++) {
        eb->bits[i] = (Ctxt *) malloc(sizeof (Ctxt));
        alloc(eb->bits[i], lambda);
    }
    eb->bitlen = bitlen;
}

void free_bits(EncBits *eb) {
    for (int i = 0; i < eb->bitlen; i++) {
        free_ctx(eb->bits[i]);
        free(eb->bits[i]);
    }
    free(eb->bits);
}

void encrypt_bits(EncBits *eb, 
                  gm_pubkey_t *pk,
                  int x) {
    for (int i = 0; i < eb->bitlen; i++) {
        int b = ((x >> i) & 1);
        encrypt(eb->bits[i], pk, b);
    }
}

int decrypt_bits(EncBits *eb,
                 gm_prvkey_t *sk) {
    int ret = 0;
    for (int i = eb->bitlen - 1; i >= 0; i--) {
        int b = decrypt(sk, eb->bits[i]);
        ret = (ret << 1) | b;
    }
    return ret;
}

int decrypt_gt(EncBits *eb,
               gm_prvkey_t *sk) {
    for (int i = eb->bitlen - 1; i >= 0; i--) {
        int b = decrypt(sk, eb->bits[i]);
        if (b == 1)
            return 1;
    }
    return 0;
}

EncBits GT(EncBits *encX, EncBits *encY, gm_pubkey_t *pk) {
    int lambda = 40;
    int bitlen = encX->bitlen;
    EncBits E, nY;
    allocate(&E, bitlen, 1);
    allocate(&nY, bitlen, 1);
    for (int i = 0; i < bitlen; i++) {
        NXOR(E.bits[i], pk, encX->bits[i], encY->bits[i]);
        NOT(nY.bits[i], pk, encY->bits[i]);
    }

    EncBits eE, eX, enY;
    allocate(&eE, bitlen, lambda);
    allocate(&eX, bitlen, lambda);
    allocate(&enY, bitlen, lambda);
    for (int i = 0; i < bitlen; i++) {
        extend(eE.bits[i], pk, E.bits[i]);
        extend(eX.bits[i], pk, encX->bits[i]);
        extend2(enY.bits[i], pk, nY.bits[i]);
    }

    EncBits T;
    allocate(&T, bitlen, lambda);
    Ctxt accum;
    alloc(&accum, lambda);
    encrypt(&accum, pk, 1);

    Ctxt tmp;
    alloc(&tmp, lambda);
    for (int i = bitlen - 1; i >= 0; i--) {
        AND(&tmp, pk, eX.bits[i], enY.bits[i]);
        AND(T.bits[i], pk, &tmp, &accum);
        AND(&tmp, pk, &accum, eE.bits[i]);
        copy(&accum, &tmp);
    }

    free_bits(&eE);
    free_bits(&eX);
    free_bits(&enY);
    free_bits(&E);
    free_bits(&nY);
    free_ctx(&accum);
    free_ctx(&tmp);
    return T;
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

int main(int argc, char *argv[]) {
    int bits = 1024;
    if (argc > 1)
        bits = atoi(argv[1]);
    gm_pubkey_t *pk;
    gm_prvkey_t *sk;
    generatekey(&pk, &sk, bits);
    std::vector<double> times[3];
    for (int i = 0; i < 1000; i++) {
        auto start = Clock::now();
        EncBits encX, encY;
        allocate(&encX, 12, 1);
        encrypt_bits(&encX, pk, 3);
        allocate(&encY, 12, 1);
        encrypt_bits(&encY, pk, 5);
        auto end = Clock::now();
        times[0].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        EncBits gt = GT(&encX, &encY, pk);
        end = Clock::now();
        times[1].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        auto dec = decrypt_gt(&gt, sk);
        end = Clock::now();
        times[2].push_back(time_as_millsecond(end - start));

        free_bits(&encX);
        free_bits(&encY);
        free_bits(&gt);
    }
     for (auto &tt : times) {
        auto md = mean_std(tt, 0);
        printf("%.3f %.4f ", md.first, md.second);
    }

    return 0;
}
