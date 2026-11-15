// alcor-chain: converts secp256k1 public keys between the compressed (33-byte) and the uncompressed (65-byte)
// SEC1 forms. The chain stores EM keys compressed but prints them uncompressed (`PUB_EM_04…`), so abieos needs
// y = sqrt(x^3 + 7) mod p. Only field arithmetic is needed (no point operations, no secrets), so this is a small
// self-contained implementation instead of a dependency on libsecp256k1.
#pragma once

#include <array>
#include <cstdint>

namespace abieos_secp256k1 {

// A 256-bit number as 8 little-endian 32-bit limbs.
using u256 = std::array<uint32_t, 8>;

// p = 2^256 - 2^32 - 977
inline constexpr u256 field_p = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
                                 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

// (p + 1) / 4: since p % 4 == 3, a^((p + 1) / 4) is a square root of a whenever one exists.
inline constexpr u256 sqrt_exponent = {0xBFFFFF0C, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF};

inline bool less_than(const u256& a, const u256& b) {
   for (int i = 7; i >= 0; --i)
      if (a[i] != b[i])
         return a[i] < b[i];
   return false;
}

inline bool is_zero(const u256& a) {
   for (auto limb : a)
      if (limb)
         return false;
   return true;
}

// a - b, requires a >= b
inline u256 subtract(const u256& a, const u256& b) {
   u256     result{};
   uint64_t borrow = 0;
   for (int i = 0; i < 8; ++i) {
      uint64_t d = uint64_t(a[i]) - b[i] - borrow;
      result[i]  = uint32_t(d);
      borrow     = (d >> 32) & 1;
   }
   return result;
}

// Reduces a 512-bit number mod p, folding the high half with 2^256 = 2^32 + 977 (mod p).
inline u256 reduce(std::array<uint32_t, 16> t) {
   for (;;) {
      std::array<uint32_t, 8> high{};
      bool                    has_high = false;
      for (int i = 0; i < 8; ++i) {
         high[i]  = t[i + 8];
         t[i + 8] = 0;
         has_high = has_high || high[i];
      }
      if (!has_high)
         break;
      uint64_t carry = 0;
      for (int i = 0; i < 16; ++i) {
         uint64_t v = uint64_t(t[i]) + carry;
         if (i < 8)
            v += uint64_t(high[i]) * 977;
         if (i >= 1 && i <= 8)
            v += high[i - 1];
         t[i]  = uint32_t(v);
         carry = v >> 32;
      }
   }
   u256 result{};
   for (int i = 0; i < 8; ++i)
      result[i] = t[i];
   while (!less_than(result, field_p))
      result = subtract(result, field_p);
   return result;
}

inline u256 add_mod(const u256& a, const u256& b) {
   std::array<uint32_t, 16> t{};
   uint64_t                 carry = 0;
   for (int i = 0; i < 8; ++i) {
      uint64_t v = uint64_t(a[i]) + b[i] + carry;
      t[i]       = uint32_t(v);
      carry      = v >> 32;
   }
   t[8] = uint32_t(carry);
   return reduce(t);
}

inline u256 mul_mod(const u256& a, const u256& b) {
   std::array<uint32_t, 16> t{};
   for (int i = 0; i < 8; ++i) {
      uint64_t carry = 0;
      for (int j = 0; j < 8; ++j) {
         uint64_t v = uint64_t(a[i]) * b[j] + t[i + j] + carry;
         t[i + j]   = uint32_t(v);
         carry      = v >> 32;
      }
      t[i + 8] = uint32_t(carry);
   }
   return reduce(t);
}

inline u256 pow_mod(const u256& base, const u256& exponent) {
   u256 result{1};
   for (int bit = 255; bit >= 0; --bit) {
      result = mul_mod(result, result);
      if ((exponent[bit / 32] >> (bit % 32)) & 1)
         result = mul_mod(result, base);
   }
   return result;
}

// x^3 + 7: the right side of the curve equation y^2 = x^3 + 7
inline u256 curve_y_squared(const u256& x) { return add_mod(mul_mod(mul_mod(x, x), x), u256{7}); }

// 32 big-endian bytes
inline u256 from_bytes(const unsigned char* bytes) {
   u256 result{};
   for (int i = 0; i < 8; ++i) {
      const unsigned char* b = bytes + 28 - 4 * i;
      result[i] = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | uint32_t(b[3]);
   }
   return result;
}

inline void to_bytes(const u256& value, unsigned char* bytes) {
   for (int i = 0; i < 8; ++i) {
      unsigned char* b = bytes + 28 - 4 * i;
      b[0]             = uint8_t(value[i] >> 24);
      b[1]             = uint8_t(value[i] >> 16);
      b[2]             = uint8_t(value[i] >> 8);
      b[3]             = uint8_t(value[i]);
   }
}

/// 33-byte compressed key (02/03 ‖ x) -> 65-byte uncompressed key (04 ‖ x ‖ y).
/// Returns false if the bytes are not a point on the curve.
inline bool decompress(const unsigned char* compressed, unsigned char* uncompressed) {
   if (compressed[0] != 0x02 && compressed[0] != 0x03)
      return false;
   const u256 x = from_bytes(compressed + 1);
   if (!less_than(x, field_p))
      return false;
   const u256 y_squared = curve_y_squared(x);
   u256       y         = pow_mod(y_squared, sqrt_exponent);
   if (mul_mod(y, y) != y_squared)
      return false;
   if ((y[0] & 1) != (compressed[0] & 1)) {
      if (is_zero(y))
         return false;
      y = subtract(field_p, y);
   }
   uncompressed[0] = 0x04;
   to_bytes(x, uncompressed + 1);
   to_bytes(y, uncompressed + 33);
   return true;
}

/// 65-byte uncompressed key (04 ‖ x ‖ y) -> 33-byte compressed key (02/03 ‖ x).
/// Returns false if the bytes are not a point on the curve.
inline bool compress(const unsigned char* uncompressed, unsigned char* compressed) {
   if (uncompressed[0] != 0x04)
      return false;
   const u256 x = from_bytes(uncompressed + 1);
   const u256 y = from_bytes(uncompressed + 33);
   if (!less_than(x, field_p) || !less_than(y, field_p) || mul_mod(y, y) != curve_y_squared(x))
      return false;
   compressed[0] = uint8_t(0x02 | (y[0] & 1));
   to_bytes(x, compressed + 1);
   return true;
}

} // namespace abieos_secp256k1
