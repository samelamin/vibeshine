/**
 * @file src/vr_pairing_bridge.cpp
 * @brief Portable framing, JSON envelope encoding/decoding, and field
 *        validation for the first-party VR pairing bridge.
 *
 * This translation unit is portable and depends only on nlohmann_json (already
 * a project dependency) and the C/C++ standard library, so it is unit-testable
 * on every platform. The Windows-specific transport implementation lives in
 * src/platform/windows/vr_pairing_bridge.cpp.
 */
#include "vr_pairing_bridge.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace vr_pairing_bridge {
  namespace {

    using json = nlohmann::json;

    constexpr std::size_t kUuidLength = 36;
    constexpr std::array<int, 5> kUuidGroupLengths = {8, 4, 4, 4, 12};

    bool is_uuid_char(char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
             (c >= 'A' && c <= 'F') || c == '-';
    }

    bool is_lower_hex_char(char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }

    bool try_parse_uint32(std::string_view raw, std::uint32_t &out) {
      out = 0;
      if (raw.empty()) {
        return false;
      }
      for (char c : raw) {
        if (c < '0' || c > '9') {
          return false;
        }
        const std::uint64_t next = static_cast<std::uint64_t>(out) * 10u +
                                   static_cast<std::uint32_t>(c - '0');
        if (next > 0xFFFFFFFFu) {
          return false;
        }
        out = static_cast<std::uint32_t>(next);
      }
      return true;
    }

    bool try_parse_int64(std::string_view raw, std::int64_t &out) {
      out = 0;
      if (raw.empty()) {
        return false;
      }
      bool negative = false;
      std::size_t i = 0;
      if (raw[0] == '-') {
        negative = true;
        i = 1;
      }
      for (; i < raw.size(); ++i) {
        char c = raw[i];
        if (c < '0' || c > '9') {
          return false;
        }
        out = out * 10 + (c - '0');
      }
      out = negative ? -out : out;
      return true;
    }

    bool try_parse_uint16(std::string_view raw, std::uint16_t &out) {
      std::uint32_t value = 0;
      if (!try_parse_uint32(raw, value)) {
        return false;
      }
      if (value > 0xFFFFu) {
        return false;
      }
      out = static_cast<std::uint16_t>(value);
      return true;
    }

    json encode_revoke_payload(std::string_view client_uuid) {
      json out;
      out["client_uuid"] = std::string {client_uuid};
      return out;
    }

  }  // namespace

  // -------- Frame parsing / writing ---------------------------------------

  bool write_frame(std::vector<std::uint8_t> &out, std::string_view payload) {
    if (payload.size() > kMaxFrameBytes) {
      return false;
    }
    const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    const auto write_index = out.size();
    out.resize(out.size() + 4u + length);
    // Little-endian uint32, per the wire contract.
    out[write_index + 0] = static_cast<std::uint8_t>(length & 0xFFu);
    out[write_index + 1] = static_cast<std::uint8_t>((length >> 8) & 0xFFu);
    out[write_index + 2] = static_cast<std::uint8_t>((length >> 16) & 0xFFu);
    out[write_index + 3] = static_cast<std::uint8_t>((length >> 24) & 0xFFu);
    std::memcpy(out.data() + write_index + 4u, payload.data(), length);
    return true;
  }

  std::optional<frame_t> try_read_frame(std::vector<std::uint8_t> &buffer) {
    if (buffer.size() < 4) {
      return std::nullopt;
    }
    std::uint32_t length = 0;
    std::memcpy(&length, buffer.data(), 4);
    if (length > kMaxFrameBytes) {
      buffer.clear();
      frame_t bad;
      bad.length = length;
      bad.truncated = true;
      return bad;
    }
    if (buffer.size() < 4u + length) {
      return std::nullopt;
    }
    frame_t out;
    out.length = length;
    out.payload.assign(buffer.begin() + 4, buffer.begin() + 4 + length);
    buffer.erase(buffer.begin(), buffer.begin() + 4u + length);
    return out;
  }

  // -------- JSON envelope helpers -----------------------------------------

  std::optional<inbound_envelope_t> parse_request(std::string_view frame) {
    json root;
    try {
      root = json::parse(std::string {frame});
    } catch (const json::exception &) {
      return std::nullopt;
    }
    if (!root.is_object()) {
      return std::nullopt;
    }
    auto version_it = root.find("v");
    auto id_it = root.find("id");
    auto op_it = root.find("op");
    auto payload_it = root.find("payload");
    if (version_it == root.end() || id_it == root.end() || op_it == root.end()) {
      return std::nullopt;
    }
    if (!version_it->is_number_unsigned() || !id_it->is_string() || !op_it->is_string()) {
      return std::nullopt;
    }
    inbound_envelope_t out;
    out.version = version_it->get<std::uint32_t>();
    out.id = id_it->get<std::string>();
    out.op = op_it->get<std::string>();
    if (payload_it != root.end()) {
      if (!payload_it->is_object()) {
        return std::nullopt;
      }
      out.payload_json = payload_it->dump();
    } else {
      out.payload_json = "{}";
    }
    return out;
  }

  std::optional<outbound_envelope_t> parse_response(std::string_view frame) {
    json root;
    try {
      root = json::parse(std::string {frame});
    } catch (const json::exception &) {
      return std::nullopt;
    }
    if (!root.is_object()) {
      return std::nullopt;
    }
    auto version_it = root.find("v");
    auto id_it = root.find("id");
    auto ok_it = root.find("ok");
    auto err_it = root.find("error");
    auto payload_it = root.find("payload");
    if (version_it == root.end() || id_it == root.end() || ok_it == root.end()) {
      return std::nullopt;
    }
    if (!version_it->is_number_unsigned() || !id_it->is_string() || !ok_it->is_boolean()) {
      return std::nullopt;
    }
    outbound_envelope_t out;
    out.version = version_it->get<std::uint32_t>();
    out.id = id_it->get<std::string>();
    out.ok = ok_it->get<bool>();
    if (err_it != root.end() && err_it->is_string()) {
      out.error = err_it->get<std::string>();
    }
    if (payload_it != root.end() && payload_it->is_object()) {
      out.payload_json = payload_it->dump();
    } else if (payload_it != root.end()) {
      return std::nullopt;
    } else {
      out.payload_json = "{}";
    }
    return out;
  }

  std::string encode_ok_response(std::uint32_t version, std::string_view id, std::string_view payload_json) {
    json payload;
    try {
      payload = json::parse(std::string {payload_json});
    } catch (const json::exception &) {
      payload = json::object();
    }
    json root;
    root["v"] = version;
    root["id"] = std::string {id};
    root["ok"] = true;
    root["payload"] = std::move(payload);
    return root.dump();
  }

  std::string encode_error_response(std::uint32_t version, std::string_view id, std::string_view error) {
    json root;
    root["v"] = version;
    root["id"] = std::string {id};
    root["ok"] = false;
    root["error"] = std::string {error};
    return root.dump();
  }

  std::string encode_revoke_notification(std::uint32_t version, std::string_view client_uuid) {
    json root;
    root["v"] = version;
    root["id"] = std::string {};
    root["op"] = std::string {op::kRevoke};
    root["payload"] = encode_revoke_payload(client_uuid);
    return root.dump();
  }

  // -------- Authorize -----------------------------------------------------

  std::optional<authorize_request_t> parse_authorize_request(std::string_view payload) {
    json root;
    try {
      root = json::parse(std::string {payload});
    } catch (const json::exception &) {
      return std::nullopt;
    }
    if (!root.is_object()) {
      return std::nullopt;
    }
    auto uuid_it = root.find("client_uuid");
    auto sha_it = root.find("client_cert_sha256");
    if (uuid_it == root.end() || sha_it == root.end()) {
      return std::nullopt;
    }
    if (!uuid_it->is_string() || !sha_it->is_string()) {
      return std::nullopt;
    }
    authorize_request_t out;
    out.client_uuid = uuid_it->get<std::string>();
    out.client_cert_sha256 = sha_it->get<std::string>();
    if (!is_uuid_string(out.client_uuid)) {
      return std::nullopt;
    }
    if (!is_lower_hex_64(out.client_cert_sha256)) {
      return std::nullopt;
    }
    return out;
  }

  std::string encode_authorize_response(const authorize_response_t &response) {
    json root;
    root["authorized"] = response.authorized;
    return root.dump();
  }

  // -------- issue_grant ---------------------------------------------------

  std::string encode_issue_grant_request(const issue_grant_request_t &request) {
    json root;
    root["client_uuid"] = request.client_uuid;
    root["client_cert_pem"] = request.client_cert_pem;
    root["client_cert_sha256"] = request.client_cert_sha256;
    root["host_cert_sha256"] = request.host_cert_sha256;
    root["client_nonce"] = request.client_nonce;
    return root.dump();
  }

  std::optional<issue_grant_response_t> parse_issue_grant_response(std::string_view payload) {
    json root;
    try {
      root = json::parse(std::string {payload});
    } catch (const json::exception &) {
      return std::nullopt;
    }
    if (!root.is_object()) {
      return std::nullopt;
    }
    auto grant_it = root.find("grant");
    auto expires_it = root.find("expires_unix");
    auto nonce_it = root.find("client_nonce");
    auto uuid_it = root.find("client_uuid");
    auto host_sha_it = root.find("host_cert_sha256");
    auto companion_sha_it = root.find("companion_cert_sha256");
    auto port_it = root.find("port");
    if (grant_it == root.end() || expires_it == root.end() || nonce_it == root.end() ||
        uuid_it == root.end() || host_sha_it == root.end() || companion_sha_it == root.end() ||
        port_it == root.end()) {
      return std::nullopt;
    }
    if (!grant_it->is_string() || !expires_it->is_number_integer() || !nonce_it->is_string() ||
        !uuid_it->is_string() || !host_sha_it->is_string() || !companion_sha_it->is_string() ||
        !port_it->is_number_unsigned()) {
      return std::nullopt;
    }
    issue_grant_response_t out;
    out.grant = grant_it->get<std::string>();
    out.expires_unix = expires_it->get<std::int64_t>();
    out.client_nonce = nonce_it->get<std::string>();
    out.client_uuid = uuid_it->get<std::string>();
    out.host_cert_sha256 = host_sha_it->get<std::string>();
    out.companion_cert_sha256 = companion_sha_it->get<std::string>();
    const auto port_value = port_it->get<std::uint32_t>();
    if (port_value == 0 || port_value > 0xFFFFu) {
      return std::nullopt;
    }
    out.port = static_cast<std::uint16_t>(port_value);

    if (out.grant.empty() || out.grant.size() > 4096) {
      return std::nullopt;
    }
    if (!is_uuid_string(out.client_uuid)) {
      return std::nullopt;
    }
    if (!is_lower_hex_64(out.client_nonce)) {
      return std::nullopt;
    }
    if (!is_lower_hex_64(out.host_cert_sha256)) {
      return std::nullopt;
    }
    if (!is_lower_hex_64(out.companion_cert_sha256)) {
      return std::nullopt;
    }
    return out;
  }

  // -------- Field validators ----------------------------------------------

  bool is_lower_hex_64(std::string_view value) {
    if (value.size() != 64) {
      return false;
    }
    for (char c : value) {
      if (!is_lower_hex_char(c)) {
        return false;
      }
    }
    return true;
  }

  bool is_uuid_string(std::string_view value) {
    if (value.size() != kUuidLength) {
      return false;
    }
    std::size_t pos = 0;
    for (std::size_t group = 0; group < kUuidGroupLengths.size(); ++group) {
      if (group > 0) {
        if (value[pos] != '-') {
          return false;
        }
        ++pos;
      }
      for (std::size_t i = 0; i < static_cast<std::size_t>(kUuidGroupLengths[group]); ++i) {
        if (!is_uuid_char(value[pos])) {
          return false;
        }
        ++pos;
      }
    }
    return pos == value.size();
  }

  bool is_pem_certificate(std::string_view value) {
    static constexpr std::string_view kHeader = "-----BEGIN CERTIFICATE-----";
    static constexpr std::string_view kFooter = "-----END CERTIFICATE-----";
    if (value.size() < kHeader.size() + kFooter.size() + 16) {
      return false;
    }
    if (value.substr(0, kHeader.size()) != kHeader) {
      return false;
    }
    auto footer_pos = value.rfind(kFooter);
    if (footer_pos == std::string_view::npos) {
      return false;
    }
    auto body_begin = kHeader.size();
    auto body_end = footer_pos;
    if (body_end <= body_begin) {
      return false;
    }
    for (std::size_t i = body_begin; i < body_end; ++i) {
      char c = value[i];
      bool in_base64_alphabet =
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
        c == '\n' || c == '\r' || c == ' ' || c == '\t';
      if (!in_base64_alphabet) {
        return false;
      }
    }
    return true;
  }

  // Internal numeric parsers used by future RPC payload shapes (kept in
  // the .cpp because they are not part of the wire contract).
  namespace internal {
    bool parse_uint32_for_test(std::string_view raw, std::uint32_t &out) {
      return try_parse_uint32(raw, out);
    }

    bool parse_int64_for_test(std::string_view raw, std::int64_t &out) {
      return try_parse_int64(raw, out);
    }

    bool parse_uint16_for_test(std::string_view raw, std::uint16_t &out) {
      return try_parse_uint16(raw, out);
    }
  }  // namespace internal
}  // namespace vr_pairing_bridge
