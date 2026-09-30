/**
 * @file src/platform/common/vr_pairing_bridge.h
 * @brief Platform-abstracted host-side interface for the first-party VR
 *        pairing bridge.
 *
 * The portable protocol/policy lives in src/vr_pairing_bridge.h. This header
 * describes the platform-specific transport, lifecycle, and HTTPS-handler
 * helpers. The Windows implementation owns:
 *   - HKLM\SOFTWARE\Vibertemis\VRBridge triad (UserSid / CompanionPath /
 *     SunshinePath) canonical-path registration,
 *   - reconnecting named-pipe client with SECURITY_SQOS_PRESENT|
 *     SECURITY_IDENTIFICATION,
 *   - one reader thread dispatching inbound authorize RPCs to the
 *     authoritative fresh resolver, and serializing outbound
 *     issue_grant / revoke notifications,
 *   - HTTPS /api/vr/capabilities and /api/vr/bootstrap handler plumbing.
 *
 * On non-Windows builds this is a stub that returns kUnsupported for every
 * capability flag.
 */
#pragma once

// standard includes
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// local includes
#include "src/vr_pairing_bridge.h"

namespace platf::vr_pairing_bridge {

  /// Bridge lifecycle state, observable by the HTTPS handlers.
  struct capabilities_t {
    /// Always the current wire schema version (1).
    std::uint32_t schema = ::vr_pairing_bridge::kSchemaVersion;
    /// Always 1: the bootstrap contract is stable.
    std::uint32_t bootstrap = 1;
    /// True only when the host is Windows, the elevated installer registered
    /// the bridge triad, the active console session exists, and the host is
    /// currently executing inside that session. Anything else means "do not
    /// advertise the capability on the HTTP route".
    bool bridge_ready = false;
    /// Human-readable reason bridge_ready is false; never logged on success.
    std::string error;
  };

  /// Snapshot the current bridge capabilities. Safe to call from any thread.
  capabilities_t get_capabilities();

  /// Validate a `client_nonce` candidate: must be exactly 64 lowercase hex
  /// characters. Portable; the bridge does not depend on platform.
  bool is_valid_client_nonce(std::string_view value);

  /// Format bytes as lowercase hex (no separator). The caller owns the
  /// output buffer (must be at least 2 * bytes.size() + 1 bytes).
  std::string to_lower_hex(std::string_view bytes);

  /// Host-cert SHA-256 (DER-encoded), lowercase hex, 64 chars.
  std::string host_cert_sha256_hex();

  /// Lowercase hex SHA-256 of any byte span. Used for both host cert and
  /// the client cert fingerprint reported by the resolver.
  std::string sha256_hex(std::string_view bytes);

  /// Lowercase hex SHA-256 of a PEM-encoded client certificate. Uses the
  /// ASN.1 DER bytes (not the PEM body) so the fingerprint matches the
  /// canonical identity already used by the resolve helper in nvhttp.
  /// Returns std::nullopt when the PEM is malformed or cannot be parsed.
  std::optional<std::string> client_cert_sha256_from_pem(std::string_view pem);

  /// Issue a pairing grant by sending `issue_grant` to the companion over
  /// the duplex channel. Returns std::nullopt when:
  ///   - the bridge is not ready (no companion registered, wrong session,
  ///     host not in active console session, etc.),
  ///   - the RPC fails (timeout, disconnected, malformed response),
  ///   - any bounded response field fails validation,
  ///   - or the returned nonce/uuid/host_pin does not match the request.
  /// The host only brokers the grant: it never persists, logs, or relays
  /// the returned credentials beyond the validated bounded envelope.
  std::optional<::vr_pairing_bridge::issue_grant_response_t>
    request_issue_grant(const ::vr_pairing_bridge::issue_grant_request_t &request);

  /// Enqueue a best-effort revocation notification. Called from
  /// nvhttp::set_client_enabled / unpair_client *without* holding
  /// client_mutex. A failed enqueue is logged but does not propagate an
  /// error: the next authorize RPC is authoritative.
  void enqueue_revoke(std::string_view client_uuid);

  /// Stop the bridge worker thread and tear down the pipe. Idempotent.
  /// Wired into the host shutdown sequence so a pending connection does
  /// not freeze the process.
  void shutdown_bridge();

}  // namespace platf::vr_pairing_bridge
