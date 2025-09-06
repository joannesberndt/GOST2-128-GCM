/*
 * GOST2-128 + GCM file encrypt/decrypt tool (streaming, block by block)
 *
  * Build:
 *   Unix/macOS: gcc gost2gcm.c -o gost2gcm -Wall
 *   Windows (MinGW): gcc gost2gcm.c -o gost2gcm -lbcrypt -Wall
 *
 * Usage:
 *   gost2gcm c <input_file>   // encrypt -> writes <input_file>.gost2
 *   gost2gcm d <input_file>   // decrypt -> strips .gost2 if present else adds .dec
 *
 * Password is requested interactively (not on the command line) with echo off.
 *
 * Output file (encryption): [IV(16 bytes)][CIPHERTEXT][TAG(16 bytes)]
 * Output file (decryption): plaintext is written block-by-block; at the end we print
 *                           whether authentication tag is OK or FAILED.
 *
 * GCM is implemented per NIST SP 800-38D:
 *   - H = E_K(0^128)
 *   - If IV length == 12, J0 = IV || 0x00000001
 *     else J0 = GHASH_H(IV || pad || 0^64 || [len(IV) in bits]_64)
 *   - CTR starts from inc32(J0) for data blocks
 *   - Tag T = E_K(J0) XOR GHASH_H(A||C||len(A)||len(C)), with AAD empty here
 *
 * Randomness:
 *   - Preferred: arc4random_buf (BSD/macOS)
 *   - Else: /dev/urandom (Unix)
 *   - Else: BCryptGenRandom (Windows)
 *   - Else (LAST RESORT): srand(time(NULL))+rand()
 *
 * NOTE: For decryption we stream plaintext out before tag verification
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

/* ---------------------- No-echo password input ---------------------- */
#if defined(_WIN32)
  #include <conio.h>
  static int get_password(char *buf, size_t maxlen) {
      fprintf(stdout, "Enter password: "); fflush(stdout);
      size_t i = 0;
      int ch;
      while ((ch = _getch()) != '\r' && ch != '\n' && ch != EOF) {
          if (ch == 3) { /* Ctrl-C */
              return -1;
          } else if (ch == 8) { /* backspace */
              if (i > 0) i--;
          } else if (i + 1 < maxlen) {
              buf[i++] = (char)ch;
          }
      }
      buf[i] = '\0';
      fprintf(stdout, "\n");
      return 0;
  }
#else
  #include <termios.h>
  #include <unistd.h>
  static int get_password(char *buf, size_t maxlen) {
      struct termios oldt, newt;
      if (tcgetattr(STDIN_FILENO, &oldt) != 0) return -1;
      newt = oldt;
      newt.c_lflag &= ~ECHO;
      if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) return -1;
      fprintf(stdout, "Enter password: "); fflush(stdout);
      if (!fgets(buf, (int)maxlen, stdin)) {
          tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
          return -1;
      }
      /* strip newline */
      size_t n = strlen(buf);
      if (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[n-1] = '\0';
      fprintf(stdout, "\n");
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
      return 0;
  }
#endif

/* ---------------------- Portable secure random ---------------------- */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <stdlib.h>
  static int secure_random_bytes(unsigned char *buf, size_t len) {
      arc4random_buf(buf, len);
      return 0;
  }
#elif defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
  static int secure_random_bytes(unsigned char *buf, size_t len) {
      NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      return (st == 0) ? 0 : -1;
  }
#else
  #include <stdio.h>
  static int secure_random_bytes(unsigned char *buf, size_t len) {
      FILE *f = fopen("/dev/urandom", "rb");
      if (!f) return -1;
      size_t r = fread(buf, 1, len, f);
      fclose(f);
      return (r == len) ? 0 : -1;
  }
#endif

/* Last-resort weak RNG (only if all above fail) */
static void fallback_weak_rng(unsigned char *buf, size_t len) {
    /* WARNING: This is NOT cryptographically secure. */
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }
}

static void get_iv_16(unsigned char iv[16]) {
    if (secure_random_bytes(iv, 16) == 0) return;
    /* fallback */
    fprintf(stderr, "WARNING: secure RNG unavailable; using weak srand(time(NULL)) fallback.\n");
    fallback_weak_rng(iv, 16);
}

/* --------------------- GOST2-128 cipher ---------------------- */

typedef uint64_t word64;

#define n1 512 /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

int x1,x2,i_;
unsigned char h2[n1];
unsigned char h1[n1*3];

static void init_hashing() {
    x1 = 0; x2 = 0;
    for (i_ = 0; i_ < n1; i_++) h2[i_] = 0;
    for (i_ = 0; i_ < n1; i_++) h1[i_] = 0;
}

static void hashing(unsigned char t1[], size_t b6) {
    static unsigned char s4[256] = 
    {   13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
        119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,
        3,88,234,94,144,118,159,239,100,17,182,173,238,68,16,79,132,54,163,52,9,58,57,55,229,192,
        170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
        212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,
        59,123,172,108,211,96,138,10,215,42,225,40,81,65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,
        131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,254,136,91,
        114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,
        223,45,48,246,186,41,148,140,107,76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,
        202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113 };

    int b1,b2,b3,b4,b5; b4=0;
    while (b6) {
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];
            x1 = h2[x2] ^= s4[b5 ^ x1];
        }
        if (x2 == n1) {
            b2 = 0; x2 = 0;
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
        }
    }
}

static void end_hash(unsigned char h4[n1]) {
    unsigned char h3[n1];
    int i, n4;
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}

/* create 64 * 64-bit subkeys from h4 hash */
static void create_keys(unsigned char h4[n1], word64 key[64]) {
  int k=0;
  for (int i=0;i<64;i++) {
      key[i]=0;
      for (int z=0;z<8;z++) key[i]=(key[i]<<8)+(h4[k++]&0xff);
  }
}

/* S-boxes / tables */
static unsigned char const k1_[16]  = { 0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 };
static unsigned char const k2_[16]  = { 0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 };
static unsigned char const k3_[16]  = { 0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB };
static unsigned char const k4_[16]  = { 0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 };
static unsigned char const k5_[16]  = { 0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 };
static unsigned char const k6_[16]  = { 0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE };
static unsigned char const k7_[16]  = { 0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC };
static unsigned char const k8_[16]  = { 0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC };
static unsigned char const k9_[16]  = { 0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 };
static unsigned char const k10_[16] = { 0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF };
static unsigned char const k11_[16] = { 0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 };
static unsigned char const k12_[16] = { 0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB };
static unsigned char const k13_[16] = { 0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC };
static unsigned char const k14_[16] = { 0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 };
static unsigned char const k15_[16] = { 0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 };
static unsigned char const k16_[16] = { 0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 };

static unsigned char k175[256], k153[256], k131[256], k109[256];
static unsigned char k87[256], k65[256], k43[256], k21[256];

static void kboxinit(void) {
    for (int i=0;i<256;i++) {
        k175[i] = k16_[i >> 4] << 4 | k15_[i & 15];
        k153[i] = k14_[i >> 4] << 4 | k13_[i & 15];
        k131[i] = k12_[i >> 4] << 4 | k11_[i & 15];
        k109[i] = k10_[i >> 4] << 4 | k9_[i & 15];
        k87[i]  = k8_[i >> 4]  << 4 | k7_[i & 15];
        k65[i]  = k6_[i >> 4]  << 4 | k5_[i & 15];
        k43[i]  = k4_[i >> 4]  << 4 | k3_[i & 15];
        k21[i]  = k2_[i >> 4]  << 4 | k1_[i & 15];
    }
}

#if __GNUC__
__inline__
#endif
static word64 f_gost(word64 x) {
    word64 y = x >> 32;
    word64 z = x & 0xffffffffULL;
    y = ((word64)k87[y>>24 & 255] << 24) | ((word64)k65[y>>16 & 255] << 16) |
        ((word64)k43[y>> 8 & 255] <<  8) | ((word64)k21[y & 255]);
    z = ((word64)k175[z>>24 & 255] << 24) | ((word64)k153[z>>16 & 255] << 16) |
        ((word64)k131[z>> 8 & 255] <<  8) | ((word64)k109[z & 255]);
    x = (y << 32) | (z & 0xffffffffULL);
    return (x<<11) | (x>>(64-11));
}

static void gostcrypt(const word64 in[2], word64 out[2], word64 key[64]) {
    word64 a = in[0], b = in[1];
    int k=0;
    for (int r=0;r<32;r++) {
        b ^= f_gost(a + key[k++]);
        a ^= f_gost(b + key[k++]);
    }
    out[0] = b; out[1] = a;
}

static void gostdecrypt(const word64 in[2], word64 out[2], word64 key[64]) {
    word64 a = in[0], b = in[1];
    int k=63;
    for (int r=0;r<32;r++) {
        b ^= f_gost(a + key[k--]);
        a ^= f_gost(b + key[k--]);
    }
    out[0] = b; out[1] = a;
}

/* ---------------------- GCM helpers (128-bit ops) ---------------------- */

typedef struct { uint64_t hi, lo; } be128; /* big-endian logical 128-bit */

static be128 load_be128(const unsigned char b[16]) {
    be128 x;
    x.hi = ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<55>>47?0:0)|0; 
    /* Implement properly: */
    x.hi = ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
           ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
    x.lo = ((uint64_t)b[8]<<56)|((uint64_t)b[9]<<48)|((uint64_t)b[10]<<40)|((uint64_t)b[11]<<32)|
           ((uint64_t)b[12]<<24)|((uint64_t)b[13]<<16)|((uint64_t)b[14]<<8)|((uint64_t)b[15]);
    return x;
}

static void store_be128(be128 x, unsigned char b[16]) {
    b[0]=(unsigned char)(x.hi>>56); b[1]=(unsigned char)(x.hi>>48);
    b[2]=(unsigned char)(x.hi>>40); b[3]=(unsigned char)(x.hi>>32);
    b[4]=(unsigned char)(x.hi>>24); b[5]=(unsigned char)(x.hi>>16);
    b[6]=(unsigned char)(x.hi>>8);  b[7]=(unsigned char)(x.hi);
    b[8]=(unsigned char)(x.lo>>56); b[9]=(unsigned char)(x.lo>>48);
    b[10]=(unsigned char)(x.lo>>40);b[11]=(unsigned char)(x.lo>>32);
    b[12]=(unsigned char)(x.lo>>24);b[13]=(unsigned char)(x.lo>>16);
    b[14]=(unsigned char)(x.lo>>8); b[15]=(unsigned char)(x.lo);
}

static be128 be128_xor(be128 a, be128 b) {
    be128 r; r.hi = a.hi ^ b.hi; r.lo = a.lo ^ b.lo; return r;
}

/* right shift by 1 bit (big-endian logical value) */
static be128 be128_shr1(be128 v) {
    be128 r;
    r.lo = (v.lo >> 1) | ((v.hi & 1) << 63);
    r.hi = (v.hi >> 1);
    return r;
}

/* left shift by 1 bit */
static be128 be128_shl1(be128 v) {
    be128 r;
    r.hi = (v.hi << 1) | (v.lo >> 63);
    r.lo = (v.lo << 1);
    return r;
}

/* GF(2^128) multiplication per SP 800-38D, right-shift method */
static be128 gf_mult(be128 X, be128 Y) {
    be128 Z = (be128){0,0};
    be128 V = Y;
    /* R = 0xE1000000000000000000000000000000 (big-endian) */
    const be128 R = { 0xE100000000000000ULL, 0x0000000000000000ULL };

    for (int i=0;i<128;i++) {
        /* test MSB of X */
        uint64_t msb = (X.hi & 0x8000000000000000ULL);
        if (msb) Z = be128_xor(Z, V);
        /* update V */
        uint64_t lsb = (V.lo & 1ULL);
        V = be128_shr1(V);
        if (lsb) V = be128_xor(V, R);
        /* shift X left */
        X = be128_shl1(X);
    }
    return Z;
}

/* GHASH update: Y <- (Y ^ X) * H */
static void ghash_update(be128 *Y, be128 H, const unsigned char block[16]) {
    be128 X = load_be128(block);
    *Y = gf_mult(be128_xor(*Y, X), H);
}

/* Encrypt a single 16-byte block with GOST2-128 */
static void gost_encrypt_block(const unsigned char in[16], unsigned char out[16], word64 key[64]) {
    word64 inw[2], outw[2];
    inw[0] = ((uint64_t)in[0]<<56)|((uint64_t)in[1]<<48)|((uint64_t)in[2]<<40)|((uint64_t)in[3]<<32)|
             ((uint64_t)in[4]<<24)|((uint64_t)in[5]<<16)|((uint64_t)in[6]<<8)|((uint64_t)in[7]);
    inw[1] = ((uint64_t)in[8]<<56)|((uint64_t)in[9]<<48)|((uint64_t)in[10]<<40)|((uint64_t)in[11]<<32)|
             ((uint64_t)in[12]<<24)|((uint64_t)in[13]<<16)|((uint64_t)in[14]<<8)|((uint64_t)in[15]);
    gostcrypt(inw, outw, key);
    out[0]=(unsigned char)(outw[0]>>56); out[1]=(unsigned char)(outw[0]>>48);
    out[2]=(unsigned char)(outw[0]>>40); out[3]=(unsigned char)(outw[0]>>32);
    out[4]=(unsigned char)(outw[0]>>24); out[5]=(unsigned char)(outw[0]>>16);
    out[6]=(unsigned char)(outw[0]>>8);  out[7]=(unsigned char)(outw[0]);
    out[8]=(unsigned char)(outw[1]>>56); out[9]=(unsigned char)(outw[1]>>48);
    out[10]=(unsigned char)(outw[1]>>40);out[11]=(unsigned char)(outw[1]>>32);
    out[12]=(unsigned char)(outw[1]>>24);out[13]=(unsigned char)(outw[1]>>16);
    out[14]=(unsigned char)(outw[1]>>8); out[15]=(unsigned char)(outw[1]);
}

/* Compute H = E_K(0^128) */
static void compute_H(unsigned char H[16], word64 key[64]) {
    unsigned char zero[16]={0};
    gost_encrypt_block(zero, H, key);
}

/* inc32 on the last 32 bits of a 128-bit counter (big-endian) */
static void inc32(unsigned char ctr[16]) {
    unsigned int c = ((unsigned int)ctr[12]<<24)|((unsigned int)ctr[13]<<16)|
                     ((unsigned int)ctr[14]<<8)|((unsigned int)ctr[15]);
    c = (c + 1) & 0xFFFFFFFFU;
    ctr[12] = (unsigned char)(c>>24);
    ctr[13] = (unsigned char)(c>>16);
    ctr[14] = (unsigned char)(c>>8);
    ctr[15] = (unsigned char)(c);
}

/* Derive J0 from IV (generic case when IV != 12 bytes) */
static void derive_J0(unsigned char J0[16], const unsigned char *iv, size_t ivlen, be128 Hbe) {
    /* Y = 0 */
    be128 Y = (be128){0,0};
    unsigned char block[16];

    /* Process full 16-byte blocks of IV */
    size_t off = 0;
    while (ivlen - off >= 16) {
        ghash_update(&Y, Hbe, iv + off);
        off += 16;
    }
    /* Last partial block (pad with zeros) */
    if (ivlen - off > 0) {
        memset(block, 0, 16);
        memcpy(block, iv + off, ivlen - off);
        ghash_update(&Y, Hbe, block);
    }
    /* Append 128-bit length block: 64-bit zeros || [len(IV) in bits]_64 */
    memset(block, 0, 16);
    uint64_t ivbits = (uint64_t)ivlen * 8ULL;
    block[8]  = (unsigned char)(ivbits>>56);
    block[9]  = (unsigned char)(ivbits>>48);
    block[10] = (unsigned char)(ivbits>>40);
    block[11] = (unsigned char)(ivbits>>32);
    block[12] = (unsigned char)(ivbits>>24);
    block[13] = (unsigned char)(ivbits>>16);
    block[14] = (unsigned char)(ivbits>>8);
    block[15] = (unsigned char)(ivbits);
    ghash_update(&Y, Hbe, block);

    store_be128(Y, J0);
}

/* Prepares GHASH lengths block for AAD(empty) and C(lenC) */
static void ghash_lengths_update(be128 *Y, be128 Hbe, uint64_t aad_bits, uint64_t c_bits) {
    unsigned char lenblk[16];
    /* [len(AAD)]_64 || [len(C)]_64 in bits, both big-endian */
    lenblk[0]=lenblk[1]=lenblk[2]=lenblk[3]=lenblk[4]=lenblk[5]=lenblk[6]=lenblk[7]=0;
    lenblk[8]  = (unsigned char)(c_bits>>56);
    lenblk[9]  = (unsigned char)(c_bits>>48);
    lenblk[10] = (unsigned char)(c_bits>>40);
    lenblk[11] = (unsigned char)(c_bits>>32);
    lenblk[12] = (unsigned char)(c_bits>>24);
    lenblk[13] = (unsigned char)(c_bits>>16);
    lenblk[14] = (unsigned char)(c_bits>>8);
    lenblk[15] = (unsigned char)(c_bits);
    ghash_update(Y, Hbe, lenblk);
}

/* Constant-time tag comparison */
static int ct_memcmp(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char r = 0;
    for (size_t i=0;i<n;i++) r |= (unsigned char)(a[i]^b[i]);
    return r; /* 0 if equal */
}

/* ---------------------- File name helpers ---------------------- */
static void add_suffix_gost2(const char *in, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.gost2", in);
}
static void strip_suffix_gost2(const char *in, char *out, size_t outsz) {
    size_t n = strlen(in);
    const char *suf = ".gost2";
    size_t m = strlen(suf);
    if (n > m && strcmp(in + (n-m), suf) == 0) {
        snprintf(out, outsz, "%.*s", (int)(n-m), in);
    } else {
        snprintf(out, outsz, "%s.dec", in);
    }
}

/* ---------------------- High-level encrypt/decrypt ---------------------- */

#define BUF_CHUNK 4096

static int encrypt_file(const char *infile, const char *outfile, word64 key[64]) {
    FILE *fi = fopen(infile, "rb");
    if (!fi) { perror("open input"); return -1; }
    FILE *fo = fopen(outfile, "wb");
    if (!fo) { perror("open output"); fclose(fi); return -1; }

    /* Compute H and J0 */
    unsigned char H[16]; compute_H(H, key);
    be128 Hbe = load_be128(H);

    unsigned char iv[16];
    get_iv_16(iv);

    /* Write IV (16 bytes) */
    if (fwrite(iv, 1, 16, fo) != 16) { perror("write IV"); fclose(fi); fclose(fo); return -1; }

    unsigned char J0[16];
    derive_J0(J0, iv, 16, Hbe);

    /* S = GHASH over ciphertext (starts at 0) */
    be128 S = (be128){0,0};

    /* Counter starts from inc32(J0) */
    unsigned char ctr[16]; memcpy(ctr, J0, 16); inc32(ctr);

    /* Streaming encrypt */
    unsigned char inbuf[BUF_CHUNK], outbuf[BUF_CHUNK];
    size_t r;
    uint64_t total_c_bytes = 0;

    while ((r = fread(inbuf, 1, BUF_CHUNK, fi)) > 0) {
        /* process r bytes in 16-byte steps */
        size_t off = 0;
        while (off < r) {
            unsigned char ks[16];
            unsigned char cblk[16];
            unsigned char pblk[16];
            size_t n = (r - off >= 16)? 16 : (r - off);

            /* keystream = E_K(ctr) */
            gost_encrypt_block(ctr, ks, key);
            inc32(ctr);

            /* P block (pad with zeros for XOR; we only write n bytes) */
            memset(pblk, 0, 16);
            memcpy(pblk, inbuf + off, n);

            for (size_t i=0;i<n;i++) cblk[i] = (unsigned char)(pblk[i] ^ ks[i]);
            if (n < 16) memset(cblk + n, 0, 16 - n); /* pad for GHASH */

            /* Update GHASH with ciphertext block (padded for partial) */
            ghash_update(&S, Hbe, cblk);

            /* Write ciphertext bytes (only n bytes) */
            if (fwrite(cblk, 1, n, fo) != n) { perror("write C"); fclose(fi); fclose(fo); return -1; }

            total_c_bytes += (uint64_t)n;
            off += n;
        }
    }
    if (ferror(fi)) { perror("read input"); fclose(fi); fclose(fo); return -1; }

    /* S <- S ⊗ H with lengths block (AAD=0, C=total_c_bytes) */
    ghash_lengths_update(&S, Hbe, 0, total_c_bytes * 8ULL);

    /* Tag T = E_K(J0) XOR S */
    unsigned char EJ0[16], Tag[16];
    gost_encrypt_block(J0, EJ0, key);
    be128 Sbe = S;
    unsigned char Sbytes[16]; store_be128(Sbe, Sbytes);
    for (int i=0;i<16;i++) Tag[i] = (unsigned char)(EJ0[i] ^ Sbytes[i]);

    /* Write TAG */
    if (fwrite(Tag, 1, 16, fo) != 16) { perror("write TAG"); fclose(fi); fclose(fo); return -1; }

    fclose(fi); fclose(fo);
    printf("Encryption completed. Wrote IV + ciphertext + tag.\n");
    return 0;
}

static int decrypt_file(const char *infile, const char *outfile, word64 key[64]) {
    FILE *fi = fopen(infile, "rb");
    if (!fi) { perror("open input"); return -1; }
    /* Determine file size to separate ciphertext from trailing tag (no full buffering) */
    if (fseek(fi, 0, SEEK_END) != 0) { perror("seek end"); fclose(fi); return -1; }
    long fsz = ftell(fi);
    if (fsz < 0) { perror("ftell"); fclose(fi); return -1; }
    if (fseek(fi, 0, SEEK_SET) != 0) { perror("seek set"); fclose(fi); return -1; }

    if (fsz < 16 + 16) { fprintf(stderr, "File too small (needs at least IV+TAG).\n"); fclose(fi); return -1; }
    long remaining = fsz;

    /* Read IV */
    unsigned char iv[16];
    if (fread(iv, 1, 16, fi) != 16) { perror("read IV"); fclose(fi); return -1; }
    remaining -= 16;

    /* Ciphertext length = total - TAG(16) */
    if (remaining < 16) { fprintf(stderr, "Missing tag.\n"); fclose(fi); return -1; }
    long ciph_len = remaining - 16;

    /* Prepare output file */
    FILE *fo = fopen(outfile, "wb");
    if (!fo) { perror("open output"); fclose(fi); return -1; }

    /* Compute H and J0 as in encryption */
    unsigned char H[16]; compute_H(H, key);
    be128 Hbe = load_be128(H);
    unsigned char J0[16];
    derive_J0(J0, iv, 16, Hbe);

    /* GHASH S over ciphertext */
    be128 S = (be128){0,0};

    /* CTR starts at inc32(J0) */
    unsigned char ctr[16]; memcpy(ctr, J0, 16); inc32(ctr);

    /* Stream: read ciphertext (excluding last 16B tag), update GHASH, decrypt and write P immediately */
    unsigned char buf[BUF_CHUNK], outbuf[BUF_CHUNK];
    long left = ciph_len;

    while (left > 0) {
        size_t to_read = (left > BUF_CHUNK)? BUF_CHUNK : (size_t)left;
        size_t r = fread(buf, 1, to_read, fi);
        if (r != to_read) { perror("read C"); fclose(fi); fclose(fo); return -1; }

        size_t off = 0;
        while (off < r) {
            unsigned char ks[16];
            unsigned char cblk[16];
            unsigned char pblk[16];
            size_t n = (r - off >= 16)? 16 : (r - off);

            /* Prepare ciphertext block with zero padding for GHASH */
            memset(cblk, 0, 16);
            memcpy(cblk, buf + off, n);

            /* GHASH over ciphertext block */
            ghash_update(&S, Hbe, cblk);

            /* keystream */
            gost_encrypt_block(ctr, ks, key);
            inc32(ctr);

            /* P = C XOR KS (only n bytes) */
            for (size_t i=0;i<n;i++) pblk[i] = (unsigned char)(cblk[i] ^ ks[i]);

            if (fwrite(pblk, 1, n, fo) != n) { perror("write P"); fclose(fi); fclose(fo); return -1; }

            off += n;
        }
        left -= (long)r;
    }

    /* Read the trailing TAG */
    unsigned char Tag[16];
    if (fread(Tag, 1, 16, fi) != 16) { perror("read TAG"); fclose(fi); fclose(fo); return -1; }

    fclose(fi);
    fclose(fo);

    /* Finalize GHASH with lengths */
    uint64_t c_bits = (uint64_t)ciph_len * 8ULL;
    ghash_lengths_update(&S, Hbe, 0, c_bits);

    /* Compute expected tag: E_K(J0) XOR S */
    unsigned char EJ0[16], Stmp[16], Tcalc[16];
    gost_encrypt_block(J0, EJ0, key);
    store_be128(S, Stmp);
    for (int i=0;i<16;i++) Tcalc[i] = (unsigned char)(EJ0[i] ^ Stmp[i]);

    /* Constant-time compare */
    int diff = ct_memcmp(Tag, Tcalc, 16);
    if (diff == 0) {
        printf("Authentication: OK\n");
        return 0;
    } else {
        printf("Authentication: FAILED\n");
        return 1; /* non-zero to indicate failure */
    }
}

/* ---------------------- Derive GOST2-128 subkeys from password ---------------------- */
static void derive_key_from_password(const char *pwd, word64 key[64]) {
    /* Follow the original code's hashing pipeline to build h4 then subkeys */
    unsigned char h4[n1];
    init_hashing();
    hashing((unsigned char*)pwd, strlen(pwd));
    end_hash(h4);
    create_keys(h4, key);
}

/* ---------------------- Main ---------------------- */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s c|d <input_file>\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 3) { usage(argv[0]); return 2; }

    const char *mode = argv[1];
    const char *infile = argv[2];

    char pwd[512];
    if (get_password(pwd, sizeof(pwd)) != 0) {
        fprintf(stderr, "Failed to read password.\n");
        return 2;
    }

    /* Init GOST2 tables and derive subkeys from password */
    kboxinit();
    word64 key[64];
    derive_key_from_password(pwd, key);
    /* Zero password buffer after use (best effort) */
    memset(pwd, 0, sizeof(pwd));

    /* Build output file name */
    char outfile[4096];
    if (mode[0]=='c' || mode[0]=='C') {
        add_suffix_gost2(infile, outfile, sizeof(outfile));
        if (encrypt_file(infile, outfile, key) != 0) return 1;
        return 0;
    } else if (mode[0]=='d' || mode[0]=='D') {
        strip_suffix_gost2(infile, outfile, sizeof(outfile));
        int rc = decrypt_file(infile, outfile, key);
        return (rc==0)?0:1;
    } else {
        usage(argv[0]);
        return 2;
    }
}
