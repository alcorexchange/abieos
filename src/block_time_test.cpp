// copyright defined in abieos/LICENSE.txt

// block_timestamp_type against a real block: block 5721 of the alcor-chain ACC testnet
// (chain id 9ae36fa71c10a5494664d3e1f9c67fba5dca35d316848a57a8df115ad306978f, 200 ms blocks, slot 0 at
// 2025-01-01). The bytes are its signed_block as state history sent it; /v1/chain/get_block 5721 on
// https://api.acc.alcor.exchange says "timestamp": "2026-11-23T17:40:38.400". Slot 298830192 (0x11cfc970).
//
// Built twice: test_abieos_block_time with the stock constants (500 ms, 2000-01-01), and
// test_abieos_block_time_acc with -DEOSIO_BLOCK_INTERVAL_MS=200 -DEOSIO_BLOCK_TIMESTAMP_EPOCH_MS=1735689600000.

#include "abieos.h"
#include "rapidjson/document.h"
#include <stdio.h>
#include <string>

extern const char* const state_history_plugin_abi;

static const char block_5721_hex[] =
    "70c9cf11000008f5804b513400000000165864666da62efc9dac441b1ddbe704dbce06f12dc05485a7eb4a001a9bd170"
    "2ff5592a8d21425fd651b6c78ca259f790720b1eb5607961bea19ae600bf87afe392ac4656dc9cf9556e28ad0dac4e0c"
    "279ab89bde5b73d046bed5ba068900000080000102000758160000010000001f228e73860735eee586f4fbe570d7663c"
    "8565974325732a6591992e8f5f1713327bf4c7858ee57c024c94e566befed42fd31fb490cd81a9442b6463dd5b97b11b"
    "0100d10100002a010100201d80d6296dcf296b89a7763bedd735df89c43f6b4f00c7660be4df96bce87b1d2fe6eea26d"
    "252e3f35d5a3bd38deb3b0f6cf377c7553ffb3eac3dd55844e06a40000a102b47a046b56163ead3ba800000000030000"
    "000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea30550000000018ac3155"
    "010000000100020508bd5eb4d4c35ada2e7e6586755ca64eb6fc0e9be6789134f47584a946cfd0010000000100000001"
    "0002bc5b4a0a4c7a6ec3f940db210871ff14a34979de3b360d8e0002de5d6ae0295b010000000000000000ea305500b0"
    "cafe4873bd3e010000000000ea305500000000a8ed3232140000000000ea30550000000018ac31550000010000000000"
    "00ea305500003f2a1ba6a24a010000000000ea305500000000a8ed3232310000000000ea30550000000018ac31558096"
    "98000000000004484f524e000000809698000000000004484f524e0000000100010300cb015816000001020300c00196"
    "9a8c766df1de226e70007dcb61e02a98c4422de6063ffbfe8677651839e5db7bd77c8fb9011f4f35b9083a2e6adb193b"
    "9902346908e498e65679bf5f176080f75bbbdb8dffbaaa91bc7eee7628f6cba5f733c1981fac1ac1f582b061a15b1695"
    "c2f6834636322b99bad6d9dfb528df66b7e1feabbf1ccbcc8e02e3288b661c55dc661fc767b2588635152b4c64211627"
    "7f025ec8ba51d3ceb97ad1e5e0a8b000a60694e76ac7b347315d1092a922d40349c95eb90d3212e2edbb4f89f84d1700";

static const char slot_hex[] = "70C9CF11"; // abieos prints hex in upper case

#if EOSIO_BLOCK_INTERVAL_MS == 200 && EOSIO_BLOCK_TIMESTAMP_EPOCH_MS == 1735689600000
static const char expected_time[] = "2026-11-23T17:40:38.400"; // what the chain says
#elif EOSIO_BLOCK_INTERVAL_MS == 500 && EOSIO_BLOCK_TIMESTAMP_EPOCH_MS == 946684800000
static const char expected_time[] = "2004-09-25T08:11:36.000"; // the same slot on a stock chain
#else
#error "no expected value for this EOSIO_BLOCK_INTERVAL_MS / EOSIO_BLOCK_TIMESTAMP_EPOCH_MS"
#endif

static int failures = 0;

static void check(bool ok, const std::string& what, const std::string& got) {
    printf("%s %s: %s\n", ok ? "ok  " : "FAIL", what.c_str(), got.c_str());
    if (!ok)
        ++failures;
}

int main() {
    abieos_context* context = abieos_create();
    if (!abieos_set_abi(context, 0, state_history_plugin_abi)) {
        printf("FAIL set ship abi: %s\n", abieos_get_error(context));
        return 1;
    }

    // binary -> json: the whole block, as Hyperion decodes it
    const char* block_json = abieos_hex_to_json(context, 0, "signed_block", block_5721_hex);
    if (!block_json) {
        printf("FAIL decode signed_block: %s\n", abieos_get_error(context));
        return 1;
    }
    rapidjson::Document block;
    block.Parse(block_json);
    std::string block_time = block.HasMember("timestamp") ? block["timestamp"].GetString() : "";
    check(block_time == expected_time, "signed_block.timestamp", block_time);
    std::string producer = block.HasMember("producer") ? block["producer"].GetString() : "";
    check(producer == "alcor.bp1", "signed_block.producer", producer);

    // binary -> json -> binary for the type alone
    const char* slot_json = abieos_hex_to_json(context, 0, "block_timestamp_type", slot_hex);
    std::string slot_time = slot_json ? slot_json : abieos_get_error(context);
    check(slot_time == std::string("\"") + expected_time + "\"", "block_timestamp_type to json", slot_time);
    std::string back = abieos_json_to_bin(context, 0, "block_timestamp_type", (std::string("\"") + expected_time + "\"").c_str())
                           ? abieos_get_bin_hex(context)
                           : abieos_get_error(context);
    check(back == slot_hex, "block_timestamp_type from json", back);

    abieos_destroy(context);
    return failures ? 1 : 0;
}
