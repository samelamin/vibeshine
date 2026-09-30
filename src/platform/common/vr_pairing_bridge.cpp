// Certificate helpers are shared; only the IPC transport is Windows-specific.
#include "src/platform/common/vr_pairing_bridge.h"
#include "src/crypto.h"
#include "src/nvhttp.h"
namespace platf::vr_pairing_bridge {
  bool is_valid_client_nonce(std::string_view value) {
    return ::vr_pairing_bridge::is_lower_hex_64(value);
  }

  std::string to_lower_hex(std::string_view bytes) {
    static constexpr char kBits[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      auto b = static_cast<std::uint8_t>(bytes[i]);
      out[i * 2 + 0] = kBits[(b >> 4) & 0x0F];
      out[i * 2 + 1] = kBits[b & 0x0F];
    }
    return out;
  }

  std::string host_cert_sha256_hex() {
    return nvhttp::vr_pairing_bridge::host_cert_sha256_hex();
  }

  std::string sha256_hex(std::string_view bytes) {
    static constexpr char kBits[] = "0123456789abcdef";
    crypto::sha256_t digest = crypto::hash(bytes);
    std::string out;
    out.resize(digest.size() * 2);
    for (std::size_t i = 0; i < digest.size(); ++i) {
      out[i * 2 + 0] = kBits[(digest[i] >> 4) & 0x0F];
      out[i * 2 + 1] = kBits[digest[i] & 0x0F];
    }
    return out;
  }

  std::optional<std::string> client_cert_sha256_from_pem(std::string_view pem) {
    if (!::vr_pairing_bridge::is_pem_certificate(pem)) {
      return std::nullopt;
    }
    try {
      auto cert = crypto::x509(pem);
      if (!cert) {
        return std::nullopt;
      }
      const int len = i2d_X509(cert.get(), nullptr);
      if (len <= 0) {
        return std::nullopt;
      }
      std::string der(static_cast<std::size_t>(len), '\0');
      auto *cursor = reinterpret_cast<unsigned char *>(der.data());
      if (i2d_X509(cert.get(), &cursor) != len) {
        return std::nullopt;
      }
      return sha256_hex(der);
    } catch (...) {
      return std::nullopt;
    }
  }


#ifndef _WIN32
  capabilities_t get_capabilities() { return {1, 1, false, "unsupported"}; }
  std::optional<::vr_pairing_bridge::issue_grant_response_t> request_issue_grant(const ::vr_pairing_bridge::issue_grant_request_t &) { return std::nullopt; }
  void enqueue_revoke(std::string_view) {}
  void shutdown_bridge() {}
#endif
}
