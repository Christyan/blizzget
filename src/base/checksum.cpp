#include "checksum.h"

uint32 update_crc(uint32 crc, void const* vbuf, uint32 length) {
  static uint32 crc_table[256];
  static bool table_computed = false;
  uint8 const* buf = (uint8*)vbuf;
  if (!table_computed) {
    for (uint32 i = 0; i < 256; i++) {
      uint32 c = i;
      for (int k = 0; k < 8; k++) {
        if (c & 1) {
          c = 0xEDB88320L ^ (c >> 1);
        } else {
          c = c >> 1;
        }
      }
      crc_table[i] = c;
    }
    table_computed = true;
  }
  for (uint32 i = 0; i < length; i++) {
    crc = crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
  }
  return crc;
}
uint32 crc32(void const* buf, uint32 length) {
  return ~update_crc(0xFFFFFFFF, buf, length);
}
uint32 crc32(std::string const& str) {
  return ~update_crc(0xFFFFFFFF, str.c_str(), str.length());
}

//////////////////////////////////////////////////////////////////

static const uint32 MD5_R[64] = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};
static uint32 MD5_K[64] = {
  0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
  0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
  0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
  0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
  0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
  0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
  0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
  0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
  0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
  0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
  0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
  0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
  0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
  0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
  0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
  0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};

MD5::MD5() {
  digest[0] = 0x67452301;
  digest[1] = 0xEFCDAB89;
  digest[2] = 0x98BADCFE;
  digest[3] = 0x10325476;
  length = 0;
  bufSize = 0;
}
void MD5::process(void const* _buf, uint32 size) {
  uint8 const* buf = (uint8*)_buf;
  while (size) {
    uint32 cur = 64 - bufSize;
    if (cur > size) cur = size;
    memcpy(buffer + bufSize, buf, cur);
    bufSize += cur;
    length += cur;
    size -= cur;
    buf += cur;
    if (bufSize == 64) run();
  }
}
void MD5::finish(void* _digest) {
  buffer[bufSize++] = 0x80;
  if (bufSize > 56) {
    if (bufSize < 64) memset(buffer + bufSize, 0, 64 - bufSize);
    run();
  }
  if (bufSize < 56) memset(buffer + bufSize, 0, 56 - bufSize);
  *(uint64*)(buffer + 56) = uint64(length) * 8;
  run();
  memcpy(_digest, digest, sizeof digest);
}
std::string MD5::format(void const* digest)
{
  std::string result(32, ' ');
  uint8 const* d = (uint8*)digest;
  for (int i = 0; i < DIGEST_SIZE; i++) {
    sprintf(&result[i * 2], "%02x", d[i]);
  }
  return result;
}
static inline uint32 rot(uint32 x, int k) {
  return (x << k) | (x >> (32 - k));
}
void MD5::run() {
  uint32* m = (uint32*)buffer;
  uint32 a = digest[0];
  uint32 b = digest[1];
  uint32 c = digest[2];
  uint32 d = digest[3];
  for (int i = 0; i < 64; i++) {
    uint32 f, g;
    if (i < 16) f = (b & c) | ((~b) & d), g = i;
    else if (i < 32) f = (d & b) | ((~d) & c), g = (i * 5 + 1) & 0x0F;
    else if (i < 48) f = b ^ c ^ d, g = (i * 3 + 5) & 0x0F;
    else f = c ^ (b | (~d)), g = (i * 7) & 0x0F;
    uint32 temp = d;
    d = c;
    c = b;
    b += rot(a + f + MD5_K[i] + m[g], MD5_R[i]);
    a = temp;
  }
  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  bufSize = 0;
}

#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

void hashlittle2(
  const void *key,       /* the key to hash */
  size_t      length,    /* length of the key */
  uint32   *pc,        /* IN: primary initval, OUT: primary hash */
  uint32   *pb)        /* IN: secondary initval, OUT: secondary hash */
{
  uint32_t a,b,c;                                          /* internal state */
  union { const void *ptr; size_t i; } u;     /* needed for Mac Powerbook G4 */

  /* Set up the internal state */
  a = b = c = 0xdeadbeef + ((uint32_t)length) + *pc;
  c += *pb;

  u.ptr = key;
  if ((u.i & 0x3) == 0) {
    const uint32_t *k = (const uint32_t *)key;         /* read 32-bit chunks */
    const uint8_t  *k8;

    /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      b += k[1];
      c += k[2];
      mix(a,b,c);
      length -= 12;
      k += 3;
    }

    switch(length)
    {
    case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
    case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
    case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
    case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
    case 8 : b+=k[1]; a+=k[0]; break;
    case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
    case 6 : b+=k[1]&0xffff; a+=k[0]; break;
    case 5 : b+=k[1]&0xff; a+=k[0]; break;
    case 4 : a+=k[0]; break;
    case 3 : a+=k[0]&0xffffff; break;
    case 2 : a+=k[0]&0xffff; break;
    case 1 : a+=k[0]&0xff; break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }

  } else if (((u.i & 0x1) == 0)) {
    const uint16_t *k = (const uint16_t *)key;         /* read 16-bit chunks */
    const uint8_t  *k8;

    /*--------------- all but last block: aligned reads and different mixing */
    while (length > 12)
    {
      a += k[0] + (((uint32_t)k[1])<<16);
      b += k[2] + (((uint32_t)k[3])<<16);
      c += k[4] + (((uint32_t)k[5])<<16);
      mix(a,b,c);
      length -= 12;
      k += 6;
    }

    /*----------------------------- handle the last (probably partial) block */
    k8 = (const uint8_t *)k;
    switch(length)
    {
    case 12: c+=k[4]+(((uint32_t)k[5])<<16);
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 11: c+=((uint32_t)k8[10])<<16;     /* fall through */
    case 10: c+=k[4];
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 9 : c+=k8[8];                      /* fall through */
    case 8 : b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 7 : b+=((uint32_t)k8[6])<<16;      /* fall through */
    case 6 : b+=k[2];
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 5 : b+=k8[4];                      /* fall through */
    case 4 : a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 3 : a+=((uint32_t)k8[2])<<16;      /* fall through */
    case 2 : a+=k[0];
             break;
    case 1 : a+=k8[0];
             break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }

  } else {                        /* need to read the key one byte at a time */
    const uint8_t *k = (const uint8_t *)key;

    /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      a += ((uint32_t)k[1])<<8;
      a += ((uint32_t)k[2])<<16;
      a += ((uint32_t)k[3])<<24;
      b += k[4];
      b += ((uint32_t)k[5])<<8;
      b += ((uint32_t)k[6])<<16;
      b += ((uint32_t)k[7])<<24;
      c += k[8];
      c += ((uint32_t)k[9])<<8;
      c += ((uint32_t)k[10])<<16;
      c += ((uint32_t)k[11])<<24;
      mix(a,b,c);
      length -= 12;
      k += 12;
    }

    /*-------------------------------- last block: affect all 32 bits of (c) */
    switch(length)                   /* all the case statements fall through */
    {
    case 12: c+=((uint32_t)k[11])<<24;
    case 11: c+=((uint32_t)k[10])<<16;
    case 10: c+=((uint32_t)k[9])<<8;
    case 9 : c+=k[8];
    case 8 : b+=((uint32_t)k[7])<<24;
    case 7 : b+=((uint32_t)k[6])<<16;
    case 6 : b+=((uint32_t)k[5])<<8;
    case 5 : b+=k[4];
    case 4 : a+=((uint32_t)k[3])<<24;
    case 3 : a+=((uint32_t)k[2])<<16;
    case 2 : a+=((uint32_t)k[1])<<8;
    case 1 : a+=k[0];
             break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }
  }

  final(a,b,c);
  *pc=c; *pb=b;
}

uint64 jenkins(void const* buf, uint32 length) {
  uint32 a, b, c;
  a = b = c = 0xDEADBEEF + length + 2;
  c += 1;

  uint32* k = (uint32*)buf;
  while (length > 12) {
    a += k[0];
    b += k[1];
    c += k[2];

    a -= c; a ^= rot(c, 4); c += b;
    b -= a; b ^= rot(a, 6); a += c;
    c -= b; c ^= rot(b, 8); b += a;
    a -= c; a ^= rot(c, 16); c += b;
    b -= a; b ^= rot(a, 19); a += c;
    c -= b; c ^= rot(b, 4); b += a;

    length -= 12;
    k += 3;
  }

  switch (length) {
  case 12: c += k[2]; b += k[1]; a += k[0]; break;
  case 11: c += k[2] & 0xFFFFFF; b += k[1]; a += k[0]; break;
  case 10: c += k[2] & 0xFFFF; b += k[1]; a += k[0]; break;
  case  9: c += k[2] & 0xFF; b += k[1]; a += k[0]; break;
  case  8: b += k[1]; a += k[0]; break;
  case  7: b += k[1] & 0xFFFFFF; a += k[0]; break;
  case  6: b += k[1] & 0xFFFF; a += k[0]; break;
  case  5: b += k[1] & 0xFF; a += k[0]; break;
  case  4: a += k[0]; break;
  case  3: a += k[0] & 0xFFFFFF; break;
  case  2: a += k[0] & 0xFFFF; break;
  case  1: a += k[0] & 0xFF; break;
  case  0: return (uint64(b) << 32) | uint64(c);
  }

  c ^= b; c -= rot(b, 14);
  a ^= c; a -= rot(c, 11);
  b ^= a; b -= rot(a, 25);
  c ^= b; c -= rot(b, 16);
  a ^= c; a -= rot(c, 4);
  b ^= a; b -= rot(a, 14);
  c ^= b; c -= rot(b, 24);

  return (uint64(b) << 32) | uint64(c);
}
uint32 hashlittle(void const* buf, uint32 length, uint32 initval) {
  uint32 a, b, c;
  a = b = c = 0xDEADBEEF + length + initval;

  uint32* k = (uint32*)buf;
  while (length > 12) {
    a += k[0];
    b += k[1];
    c += k[2];

    a -= c; a ^= rot(c, 4); c += b;
    b -= a; b ^= rot(a, 6); a += c;
    c -= b; c ^= rot(b, 8); b += a;
    a -= c; a ^= rot(c, 16); c += b;
    b -= a; b ^= rot(a, 19); a += c;
    c -= b; c ^= rot(b, 4); b += a;

    length -= 12;
    k += 3;
  }

  switch (length) {
  case 12: c += k[2]; b += k[1]; a += k[0]; break;
  case 11: c += k[2] & 0xFFFFFF; b += k[1]; a += k[0]; break;
  case 10: c += k[2] & 0xFFFF; b += k[1]; a += k[0]; break;
  case  9: c += k[2] & 0xFF; b += k[1]; a += k[0]; break;
  case  8: b += k[1]; a += k[0]; break;
  case  7: b += k[1] & 0xFFFFFF; a += k[0]; break;
  case  6: b += k[1] & 0xFFFF; a += k[0]; break;
  case  5: b += k[1] & 0xFF; a += k[0]; break;
  case  4: a += k[0]; break;
  case  3: a += k[0] & 0xFFFFFF; break;
  case  2: a += k[0] & 0xFFFF; break;
  case  1: a += k[0] & 0xFF; break;
  case  0: return c;
  }

  c ^= b; c -= rot(b, 14);
  a ^= c; a -= rot(c, 11);
  b ^= a; b -= rot(a, 25);
  c ^= b; c -= rot(b, 16);
  a ^= c; a -= rot(c, 4);
  b ^= a; b -= rot(a, 14);
  c ^= b; c -= rot(b, 24);

  return c;
}

// Arguments:
//  header: Pointer to the memory containing the header
//  archive_index: Number of the data file the record is stored in (e.g. xxx in data.xxx)
//  archive_offset: Offset of the header inside the archive file
// Precondition: Header is at least 0x1e bytes (e.g a full header)
// Precondition: checksum_a has already been calculated and stored in the header
// Assumption: Code is written assuming little endian.
uint32_t checksum(void const* buf, uint16_t archive_index, uint32_t archive_offset) {
    // Table is extracted from Agent.exe 8020. Hasn't changed for quite a while
    static uint32_t TABLE_16C57A8[0x10] = {
        0x049396b8, 0x72a82a9b, 0xee626cca, 0x9917754f, 0x15de40b1, 0xf5a8a9b6, 0x421eac7e, 0xa9d55c9a,
        0x317fd40c, 0x04faf80d, 0x3d6be971, 0x52933cfd, 0x27f64b7d, 0xc6f5c11b, 0xd5757e3a, 0x6c388745,
    };

    // Top two bits of the offset must be set to the bottom two bits of the archive index
    uint32_t offset = (archive_offset & 0x3fffffff) | (archive_index & 3) << 30;
   
    uint32_t encoded_offset = TABLE_16C57A8[(offset + 0x1e) & 0xf] ^ (offset + 0x1e);
   
    uint32_t hashed_header = 0;
    for (int i = 0; i < 0x1a; i++) { // offset of checksum_b in header
        ((uint8_t *)&hashed_header)[(i + offset) & 3] ^= ((uint8_t*)buf)[i];
    }
   
    uint32_t checksum_b = 0;
    for (int j = 0; j < 4; j++) {
        int i = j + 0x1a + offset;
        ((uint8_t *)&checksum_b)[j] = ((uint8_t *)&hashed_header)[i & 3] ^ ((uint8_t *)&encoded_offset)[i & 3];
    }
    return checksum_b;
}
