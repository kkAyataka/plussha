// Copyright (C) 2017 kkAyataka
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef PLUSSHA_HPP__
#define PLUSSHA_HPP__

#include <vector>

/** Version number of plussha.
 * 0x01020304 -> 1.2.3.4 */
#define PLUSAES_VERSION 0x00010000

namespace plussha {
namespace detail {

const int kMsgSizeBytes = 8; // 8-byte, 64-bit. Max message size is 2<<64-bit
const int kWordBytes = 4; // 4-byte, 32-bit
const int kWordBits = 32;
typedef unsigned int Word;

const int kBlockBytes = 64; // 64-byte, 512-bit
class Block {
public:
    Word w[16]; // 32-bit * 16 = 64-byte, 512-bit
    Word & operator[](const int index) {
        return w[index];
    }
    const Word & operator[](const int index) const {
        return w[index];
    }
    Block() {}
    Block(const unsigned char * data) {
        const int word_count = sizeof(w) / sizeof(Word);
        for (int i = 0; i < word_count; ++i) {
            const unsigned char * pt = data + i * kWordBytes;
            w[i] = ((*(pt + 0) << 24) & 0xFF000000) |
                   ((*(pt + 1) << 16) & 0x00FF0000) |
                   ((*(pt + 2) <<  8) & 0x0000FF00) |
                   ((*(pt + 3)      ) & 0x00000FF);


        }
    }
};

const unsigned int kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const unsigned int kInitialHash[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

inline Word rotr(const unsigned int n, const Word x) {
    return (x >> n) | (x << (kWordBits - n));
}

inline Word shr(const unsigned int n, const Word x) {
    return (x >> n);
}

inline Word ch(const Word x, const Word y, const Word z) {
    return (x & y) ^ (~x & z);
}

inline Word maj(const Word x, const Word y, const Word z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline Word l_sigma_0(const Word x) {
    return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
}

inline Word l_sigma_1(const Word x) {
    return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
}

inline Word s_sigma_0(const Word x) {
    return rotr(7, x) ^ rotr(18, x) ^ shr(3, x);
}

inline Word s_sigma_1(const Word x) {
    return rotr(17, x) ^ rotr(19, x) ^ shr(10, x);
}

inline Word add(const Word x, const Word y) {
    return (x + y);
}

inline std::vector<unsigned char> get_padding(const unsigned long long data_size) {
    unsigned int padding_size = kBlockBytes - (data_size % kBlockBytes);
    padding_size += (padding_size >= (kMsgSizeBytes + 1)) ? 0 : kBlockBytes;

    std::vector<unsigned char> padding(padding_size);
    padding[0] = 0x80;

    const auto data_bits = data_size * 8;
    padding[padding_size - 7] = (data_bits >> 56) & 0xFF;
    padding[padding_size - 6] = (data_bits >> 48) & 0xFF;
    padding[padding_size - 8] = (data_bits >> 40) & 0xFF;
    padding[padding_size - 5] = (data_bits >> 32) & 0xFF;
    padding[padding_size - 4] = (data_bits >> 24) & 0xFF;
    padding[padding_size - 3] = (data_bits >> 16) & 0xFF;
    padding[padding_size - 2] = (data_bits >>  8) & 0xFF;
    padding[padding_size - 1] = (data_bits      ) & 0xFF;

    return padding;
}

} // namespace detail

typedef enum {
    kErrorOk = 0,
    kErrorFailed = 1,
} Error;

inline Error sha256(const unsigned char * data, const unsigned long long data_size, unsigned char (*hash)[32]) {
    std::vector<detail::Word> h_(8);
    for (int i = 0; i < h_.size(); ++i) {
        h_[i] = detail::kInitialHash[i];
    }

    const unsigned int block_count = static_cast<unsigned int>(data_size / detail::kBlockBytes);
    const auto padding = detail::get_padding(data_size);

    std::vector<detail::Block> last_blocks((padding.size() <= detail::kBlockBytes) ? 1 : 2);

    unsigned char rem_data[detail::kBlockBytes] = {};
    const unsigned long rem_size = data_size % detail::kBlockBytes;
    if (rem_size) {
        memcpy(rem_data, &data[data_size - rem_size], rem_size);
    }
    memcpy(rem_data + rem_size, &padding[0], detail::kBlockBytes - rem_size);
    last_blocks[0] = detail::Block(rem_data);

    if (last_blocks.size() >= 2) {
        last_blocks[1] = detail::Block(&(padding[padding.size() - detail::kBlockBytes]));
    }

    for (int i = 0; i < block_count + last_blocks.size(); ++i) {
        detail::Word a = h_[0];
        detail::Word b = h_[1];
        detail::Word c = h_[2];
        detail::Word d = h_[3];
        detail::Word e = h_[4];
        detail::Word f = h_[5];
        detail::Word g = h_[6];
        detail::Word h = h_[7];

        detail::Block block;
        if (i < block_count) {
            block = detail::Block(data + i * detail::kBlockBytes);
        }
        else {
            block = last_blocks[i - block_count];
        }

        detail::Word w[64] = {};
        for (int t = 0; t < 64; ++t) {
            if (t < 16) {
                w[t] = block[t];
            }
            else {
                w[t] = detail::s_sigma_1(w[t - 2]) + w[t - 7] +
                    detail::s_sigma_0(w[t - 15]) + w[t - 16];
            }
        }

        for (int t = 0; t < 64; ++t) {
            const detail::Word t1 = h + detail::l_sigma_1(e) + detail::ch(e, f, g) + detail::kK[t] + w[t];
            const detail::Word t2 = detail::l_sigma_0(a) + detail::maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h_[0] = a + h_[0];
        h_[1] = b + h_[1];
        h_[2] = c + h_[2];
        h_[3] = d + h_[3];
        h_[4] = e + h_[4];
        h_[5] = f + h_[5];
        h_[6] = g + h_[6];
        h_[7] = h + h_[7];
    }

    for (auto i = 0; i < 8; ++i) {
        (*hash)[i * 4 + 0] = h_[i] >> 24 & 0xFF;
        (*hash)[i * 4 + 1] = h_[i] >> 16 & 0xFF;
        (*hash)[i * 4 + 2] = h_[i] >>  8 & 0xFF;
        (*hash)[i * 4 + 3] = h_[i]       & 0xFF;
    }

    return kErrorOk;
}

} // namespace plussha

#endif // PLUSSHA_HPP__
