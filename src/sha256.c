#include "sha256.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} Sha256;

#define ROTR32(v, n) (((v) >> (n)) | ((v) << (32u - (n))))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void transform(Sha256 *s, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t a = w[i - 15], b = w[i - 2];
        uint32_t s0 = ROTR32(a, 7) ^ ROTR32(a, 18) ^ (a >> 3);
        uint32_t s1 = ROTR32(b, 17) ^ ROTR32(b, 19) ^ (b >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a=s->h[0], b=s->h[1], c=s->h[2], d=s->h[3];
    uint32_t e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void update(Sha256 *s, const uint8_t *data, size_t len) {
    s->bits += (uint64_t)len * 8u;
    while (len) {
        size_t take = sizeof(s->block) - s->used;
        if (take > len) take = len;
        memcpy(s->block + s->used, data, take);
        s->used += take; data += take; len -= take;
        if (s->used == sizeof(s->block)) { transform(s, s->block); s->used = 0; }
    }
}

static void finish(Sha256 *s, uint8_t digest[32]) {
    uint64_t bits = s->bits;
    uint8_t one = 0x80;
    update(s, &one, 1);
    uint8_t zero[64] = {0};
    size_t pad = s->used <= 56 ? 56 - s->used : 120 - s->used;
    update(s, zero, pad);
    uint8_t length[8];
    for (int i = 0; i < 8; i++) length[7 - i] = (uint8_t)(bits >> (i * 8));
    update(s, length, sizeof(length));
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(s->h[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(s->h[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(s->h[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)s->h[i];
    }
}

int sha256_fd(int fd, char hex[65]) {
    Sha256 s = {{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}, 0, {0}, 0};
    uint8_t buf[64u * 1024u];
    off_t off = 0;
    for (;;) {
        ssize_t got = pread(fd, buf, sizeof(buf), off);
        if (got < 0) { if (errno == EINTR) continue; return -1; }
        if (!got) break;
        update(&s, buf, (size_t)got);
        off += got;
        if (off < 0) { errno = EFBIG; return -1; }
    }
    uint8_t digest[32];
    finish(&s, digest);
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15u];
    }
    hex[64] = '\0';
    return 0;
}

void sha256_bytes(const void *data, size_t len, char hex[65]) {
    Sha256 s = {{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}, 0, {0}, 0};
    update(&s, data, len);
    uint8_t digest[32];
    finish(&s, digest);
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15u];
    }
    hex[64] = '\0';
}
