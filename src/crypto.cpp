#include <algorithm>
#include <array>
#include <cstdint>
#include "../include/eosio/crypto.hpp"
#include "../include/eosio/from_bin.hpp"
#include "../include/eosio/from_json.hpp"
#include "../include/eosio/to_bin.hpp"
#include "../include/eosio/to_json.hpp"
#include <string>
#include <string_view>

#include "abieos_ripemd160.hpp"
#include "abieos_secp256k1.hpp"

using namespace eosio;

namespace {

// variant indexes of public_key and signature
enum key_type : uint8_t {
    k1 = 0,
    r1 = 1,
    wa = 2,
    em = 3, // alcor-chain
    ed = 4, // alcor-chain
};

// variant indexes of private_key
enum private_key_type : uint8_t {
    pvt_k1 = 0,
    pvt_r1 = 1,
    pvt_em = 2, // alcor-chain
    pvt_ed = 3, // alcor-chain
};

constexpr char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

constexpr auto create_base58_map() {
    std::array<int8_t, 256> base58_map{{0}};
    for (unsigned i = 0; i < base58_map.size(); ++i)
        base58_map[i] = -1;
    for (unsigned i = 0; i < sizeof(base58_chars); ++i)
        base58_map[base58_chars[i]] = i;
    return base58_map;
}

constexpr auto base58_map = create_base58_map();

template <typename Container>
void base58_to_binary(Container& result, std::string_view s) {
    std::size_t offset = result.size();
    for (auto& src_digit : s) {
        int carry = base58_map[static_cast<uint8_t>(src_digit)];
        check(carry >= 0,
            ::eosio::convert_json_error(::eosio::from_json_error::expected_key));
        for (std::size_t i = offset; i < result.size(); ++i) {
            auto& result_byte = result[i];
            int x = static_cast<uint8_t>(result_byte) * 58 + carry;
            result_byte = x;
            carry = x >> 8;
        }
        if (carry)
            result.push_back(static_cast<uint8_t>(carry));
    }
    for (auto& src_digit : s)
        if (src_digit == '1')
            result.push_back(0);
        else
            break;
    std::reverse(result.begin() + offset, result.end());
}

template <typename Container>
std::string binary_to_base58(const Container& bin) {
    std::string result("");
    for (auto byte : bin) {
        static_assert(sizeof(byte) == 1);
        int carry = static_cast<uint8_t>(byte);
        for (auto& result_digit : result) {
            int x = (base58_map[result_digit] << 8) + carry;
            result_digit = base58_chars[x % 58];
            carry = x / 58;
        }
        while (carry) {
            result.push_back(base58_chars[carry % 58]);
            carry = carry / 58;
        }
    }
    for (auto byte : bin)
        if (byte)
            break;
        else
            result.push_back('1');
    std::reverse(result.begin(), result.end());
    return result;
}

template <typename... Container>
std::array<unsigned char, 20> digest_suffix_ripemd160(const Container&... data) {
    std::array<unsigned char, 20> digest;
    abieos_ripemd160::ripemd160_state self;
    abieos_ripemd160::ripemd160_init(&self);
    (abieos_ripemd160::ripemd160_update(&self, data.data(), data.size()), ...);
    check( abieos_ripemd160::ripemd160_digest(&self, digest.data()),
        convert_json_error(eosio::from_json_error::invalid_signature) );
    return digest;
}


template <typename Key>
Key string_to_key(std::string_view s, key_type type, std::string_view suffix) {
    std::vector<char> whole;
    whole.push_back(uint8_t{type});
    base58_to_binary(whole, s);
    check(whole.size() > 5,
        convert_json_error(eosio::from_json_error::expected_key));
    auto ripe_digest = digest_suffix_ripemd160(std::string_view(whole.data() + 1, whole.size() - 5), suffix);
    check(memcmp(ripe_digest.data(), whole.data() + whole.size() - 4, 4)==0,
        convert_json_error(from_json_error::expected_key));
    whole.erase(whole.end() - 4, whole.end());
    return convert_from_bin<Key>(whole);
}

template <typename Key>
std::string key_to_string(const Key& key, std::string_view suffix, const char* prefix) {
    auto whole = convert_to_bin(key);
    auto ripe_digest = digest_suffix_ripemd160(std::string_view(whole.data() + 1, whole.size() - 1), suffix);
    whole.insert(whole.end(), ripe_digest.data(), ripe_digest.data() + 4);
    return prefix + binary_to_base58(std::string_view(whole.data() + 1, whole.size() - 1));
}

// alcor-chain: EM and ED string forms, exactly as alcor-chain's fc prints them (to_string), so JSON from abieos
// matches the chain API:
//   PUB_EM_04<x y>    hex of the uncompressed point, no 0x     PUB_ED_<base58>  raw 32-byte key, no checksum
//   SIG_EM_0x<r s v>  hex of the 65 bytes                      SIG_ED_<base58>  public key 32 ‖ signature 64
//   PVT_EM_0x<hex>    the raw 32-byte secret                   PVT_ED_<base58>  64-byte libsodium secret key
// Hex is printed lowercase. Parsing accepts what fc accepts: an optional "0x", hex in any case, and for EM keys
// also the compressed form (02/03 ‖ x) and the uncompressed form without 04.

constexpr char lower_hex_digits[] = "0123456789abcdef";

template <typename Container>
std::string binary_to_hex(const Container& bin) {
    std::string result;
    for (auto byte : bin) {
        result.push_back(lower_hex_digits[static_cast<uint8_t>(byte) >> 4]);
        result.push_back(lower_hex_digits[static_cast<uint8_t>(byte) & 15]);
    }
    return result;
}

// fc's ethereum::trim: an optional lowercase "0x"
std::string_view trim_hex_prefix(std::string_view s) {
    return s.substr(0, 2) == "0x" ? s.substr(2) : s;
}

std::vector<char> hex_to_binary(std::string_view s, from_json_error error) {
    std::vector<char> result;
    check(s.size() % 2 == 0 && unhex(std::back_inserter(result), s.begin(), s.end()), convert_json_error(error));
    return result;
}

// fc rejects base58 strings longer than the longest encoding of the type before decoding them
std::vector<char> base58_to_bytes(std::string_view s, std::size_t max_length, from_json_error error) {
    check(s.size() <= max_length, convert_json_error(error));
    std::vector<char> result;
    base58_to_binary(result, s);
    return result;
}

template <typename Variant, std::size_t Index>
Variant variant_from_bytes(const std::vector<char>& bytes, from_json_error error) {
    std::variant_alternative_t<Index, Variant> data;
    check(bytes.size() == data.size(), convert_json_error(error));
    std::copy(bytes.begin(), bytes.end(), data.begin());
    return Variant(std::in_place_index<Index>, data);
}

std::string em_public_key_to_string(const ecc_public_key& key) {
    std::array<unsigned char, 65> uncompressed;
    if (abieos_secp256k1::decompress(reinterpret_cast<const unsigned char*>(key.data()), uncompressed.data()))
        return "PUB_EM_" + binary_to_hex(uncompressed);
    // Not a point on the curve. The node cannot print such a key (fc throws), but the chain does not check EM keys
    // when it stores an authority, so one can reach the state. Print the stored bytes as the compressed form,
    // which fc and abieos both parse back to the same bytes, rather than fail the whole block or table row.
    return "PUB_EM_" + binary_to_hex(key);
}

public_key em_public_key_from_string(std::string_view s) {
    constexpr auto error = from_json_error::expected_public_key;
    auto hex = trim_hex_prefix(s);
    ecc_public_key key;
    if (hex.size() == 66) {
        // compressed: 02/03 ‖ x; like fc, not checked against the curve
        auto bytes = hex_to_binary(hex, error);
        check(bytes[0] == 0x02 || bytes[0] == 0x03, convert_json_error(error));
        std::copy(bytes.begin(), bytes.end(), key.begin());
    } else if (hex.size() == 128 || hex.size() == 130) {
        // uncompressed: [04] ‖ x ‖ y; compress() checks the 04 and that the point is on the curve
        auto bytes = hex_to_binary(hex, error);
        std::array<unsigned char, 65> uncompressed;
        uncompressed[0] = 0x04;
        std::copy(bytes.begin(), bytes.end(), uncompressed.begin() + 65 - bytes.size());
        check(abieos_secp256k1::compress(uncompressed.data(), reinterpret_cast<unsigned char*>(key.data())),
              convert_json_error(error));
    } else {
        check(false, convert_json_error(error));
    }
    return public_key(std::in_place_index<key_type::em>, key);
}
} // namespace

std::string eosio::public_key_to_string(const public_key& key) {
    if (key.index() == key_type::k1) {
        return key_to_string(key, "K1", "PUB_K1_");
    } else if (key.index() == key_type::r1) {
        return key_to_string(key, "R1", "PUB_R1_");
    } else if (key.index() == key_type::wa) {
        return key_to_string(key, "WA", "PUB_WA_");
    } else if (key.index() == key_type::em) {
        return em_public_key_to_string(std::get<key_type::em>(key));
    } else if (key.index() == key_type::ed) {
        return "PUB_ED_" + binary_to_base58(std::get<key_type::ed>(key));
    } else {
       check(false, convert_json_error(eosio::from_json_error::expected_public_key));
       __builtin_unreachable();
    }
}

public_key eosio::public_key_from_string(std::string_view s) {
    public_key result;
    if (s.substr(0, 3) == "EOS") {
        return string_to_key<public_key>(s.substr(3), key_type::k1, "");
    } else if (s.substr(0, 7) == "PUB_K1_") {
        return string_to_key<public_key>(s.substr(7), key_type::k1, "K1");
    } else if (s.substr(0, 7) == "PUB_R1_") {
        return string_to_key<public_key>(s.substr(7), key_type::r1, "R1");
    } else if (s.substr(0, 7) == "PUB_WA_") {
        return string_to_key<public_key>(s.substr(7), key_type::wa, "WA");
    } else if (s.substr(0, 7) == "PUB_EM_") {
        return em_public_key_from_string(s.substr(7));
    } else if (s.substr(0, 7) == "PUB_ED_") {
        constexpr auto error = from_json_error::expected_public_key;
        return variant_from_bytes<public_key, key_type::ed>(base58_to_bytes(s.substr(7), 44, error), error);
    } else {
       check(false, convert_json_error(from_json_error::expected_public_key));
       __builtin_unreachable();
    }
}

std::string eosio::private_key_to_string(const private_key& private_key) {
    if (private_key.index() == private_key_type::pvt_k1)
        return key_to_string(private_key, "K1", "PVT_K1_");
    else if (private_key.index() == private_key_type::pvt_r1)
        return key_to_string(private_key, "R1", "PVT_R1_");
    else if (private_key.index() == private_key_type::pvt_em)
        return "PVT_EM_0x" + binary_to_hex(std::get<private_key_type::pvt_em>(private_key));
    else if (private_key.index() == private_key_type::pvt_ed)
        return "PVT_ED_" + binary_to_base58(std::get<private_key_type::pvt_ed>(private_key));
    else {
       check(false, convert_json_error(from_json_error::expected_private_key));
       __builtin_unreachable();
    }
}

private_key eosio::private_key_from_string(std::string_view s) {
    constexpr auto error = from_json_error::expected_private_key;
    if (s.substr(0, 7) == "PVT_K1_")
        return string_to_key<private_key>(s.substr(7), key_type::k1, "K1");
    else if (s.substr(0, 7) == "PVT_R1_")
        return string_to_key<private_key>(s.substr(7), key_type::r1, "R1");
    else if (s.substr(0, 7) == "PVT_EM_")
        return variant_from_bytes<private_key, private_key_type::pvt_em>(
            hex_to_binary(trim_hex_prefix(s.substr(7)), error), error);
    else if (s.substr(0, 7) == "PVT_ED_")
        return variant_from_bytes<private_key, private_key_type::pvt_ed>(base58_to_bytes(s.substr(7), 88, error),
                                                                         error);
    else if (s.substr(0, 4) == "PVT_") {
       check(false, convert_json_error(from_json_error::expected_private_key));
       __builtin_unreachable();
    } else {
        std::vector<char> whole;
        base58_to_binary(whole, s);
        check(whole.size() >= 5, convert_json_error(from_json_error::expected_private_key));
        whole[0] = private_key_type::pvt_k1;
        whole.erase(whole.end() - 4, whole.end());
        return convert_from_bin<private_key>(whole);
    }
}

std::string eosio::signature_to_string(const eosio::signature& signature) {
    if (signature.index() == key_type::k1)
        return key_to_string(signature, "K1", "SIG_K1_");
    else if (signature.index() == key_type::r1)
        return key_to_string(signature, "R1", "SIG_R1_");
    else if (signature.index() == key_type::wa)
        return key_to_string(signature, "WA", "SIG_WA_");
    else if (signature.index() == key_type::em)
        return "SIG_EM_0x" + binary_to_hex(std::get<key_type::em>(signature));
    else if (signature.index() == key_type::ed)
        return "SIG_ED_" + binary_to_base58(std::get<key_type::ed>(signature));
    else {
       check(false, convert_json_error(eosio::from_json_error::expected_signature));
       __builtin_unreachable();
    }
}

signature eosio::signature_from_string(std::string_view s) {
    if (s.size() >= 7 && s.substr(0, 7) == "SIG_K1_")
        return string_to_key<signature>(s.substr(7), key_type::k1, "K1");
    else if (s.size() >= 7 && s.substr(0, 7) == "SIG_R1_")
        return string_to_key<signature>(s.substr(7), key_type::r1, "R1");
    else if (s.size() >= 7 && s.substr(0, 7) == "SIG_WA_")
        return string_to_key<signature>(s.substr(7), key_type::wa, "WA");
    else if (s.substr(0, 7) == "SIG_EM_") {
        constexpr auto error = from_json_error::expected_signature;
        return variant_from_bytes<signature, key_type::em>(hex_to_binary(trim_hex_prefix(s.substr(7)), error), error);
    } else if (s.substr(0, 7) == "SIG_ED_") {
        constexpr auto error = from_json_error::expected_signature;
        return variant_from_bytes<signature, key_type::ed>(base58_to_bytes(s.substr(7), 132, error), error);
    } else {
       check(false, convert_json_error(eosio::from_json_error::expected_signature));
       __builtin_unreachable();
    }
}

namespace eosio {
    std::string to_base58(const char* d, size_t s ) {
        return binary_to_base58( std::string_view(d,s) );
    }

    std::vector<char> from_base58(const std::string_view& s) {
        std::vector<char> ret;
        base58_to_binary(ret, s);
        return ret;
    }
}
