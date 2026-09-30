/**
 * @file src/vr_pairing_bridge.h
 * @brief Vibeshine half of the first-party VR pairing bridge protocol contract.
 *
 * This header is portable: the JSON shape, framing, RPC envelope, and policy
 * helpers here are consumed by unit tests on every platform. The Windows-only
 * transport lives in src/platform/windows/vr_pairing_bridge.cpp.
 *
 * Topology (host = Sunshine.exe, companion = per-user Android-broker helper):
 *
 *     Android client ---TLS/pinned--> Companion ---IPC pipe--> Sunshine host
 *
 * The COMPANION owns the named-pipe server instance
 * (\\.\pipe\VibertemisVRBridge-<sessionid>). The HOST is the client that
 * reconnects on failure with bounded backoff. The companion runs per-user and
 * is unsigned; we do not assume Authenticode on it.
 *
 * Trust boundary (from the Agy adjudication):
 *   - sunshinesvc::DuplicateTokenForSession duplicates the LocalSystem token and
 *     only changes its session id, so a Sunshine host that entered the active
 *     console session as SYSTEM may legitimately own a LocalSystem identity.
 *     We therefore never assume the host is the user.
 *   - Registration values UserSid / CompanionPath / SunshinePath under
 *     HKLM\SOFTWARE\Vibertemis\VRBridge are written by the elevated Windows
 *     installer (the per-session VR helper setup helper). They are canonical
 *     absolute paths. The elevated helper writes them; runtime does not.
 *   - The malicious admin/SYSTEM and same-user malware threat models already
 *     hold the private keys needed to forge the Sunshine TLS identity, so we
 *     do not gain anything by trying to lock them out further. We *do* protect
 *     other users on the host and remote attackers from impersonating the
 *     companion.
 *   - The HOST validates the pipe SERVER (companion) on every connection:
 *     GetNamedPipeServerProcessId, QueryFullProcessImageNameW against the
 *     registered CompanionPath, Identification-level ImpersonateNamedPipeClient
 *     to read TokenUser and compare it to UserSid, plus session id equality
 *     with the active console session and the host's own session. The pipe is
 *     opened with SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION so the host
 *     can inspect the peer without granting the peer impersonation rights.
 *     The COMPANION is the side that uses ImpersonateNamedPipeClient to
 *     elevate to a full impersonation token for its own server-side checks
 *     (e.g. resolving SunshinePath against the host identity). The host never
 *     impersonates its peer.
 *   - The host only brokers the issue_grant RPC: it never persists the grant,
 *     never logs it, and only relays the validated bounded response fields.
 *   - The fresh authorize RPC is authoritative. A revoke notification is best-
 *     effort; if it is missed the next authorize still denies the disabled
 *     record.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vr_pairing_bridge {

  // -------- Wire-level constants ------------------------------------------

  /// Wire schema version. Bumped only when the JSON shape changes.
  inline constexpr std::uint32_t kSchemaVersion = 1;

  /// Maximum JSON payload for a single message (RFC: 65536).
  inline constexpr std::size_t kMaxFrameBytes = 65536;

  /// Hard ceiling for inbound bootstrap POST bodies (defence in depth; the
  /// HTTPS listener enforces the same cap independently).
  inline constexpr std::size_t kMaxBootstrapBodyBytes = 16 * 1024;

  /// Maximum number of outstanding RPC calls on a single duplex channel.
  inline constexpr std::size_t kMaxOutstandingRpcs = 32;

  /// Default deadline for an outstanding RPC (5 seconds).
  inline constexpr std::chrono::milliseconds kDefaultRpcDeadline {5000};

  /// Pipe name prefix; the active console session id is appended so each
  /// session has its own private named-pipe instance.
  inline constexpr std::string_view kPipeNamePrefix = R"(\\.\pipe\VibertemisVRBridge-)";

  /// HKLM registry path used by the elevated installer (or sunshinesvc at
  /// first user launch) to register the bridge triad.
  inline constexpr std::string_view kRegistryKey = R"(SOFTWARE\Vibertemis\VRBridge)";

  /// Companion broker TCP port the Android client connects to.
  inline constexpr std::uint16_t kCompanionBrokerPort = 28540;

  // -------- Protocol operations --------------------------------------------

  /// JSON `op` field values for inbound (companion -> host) and outbound
  /// (host -> companion) messages. Wire-compatible; do not rename.
  namespace op {
    /// Companion requests an authorization decision for the current TLS
    /// client. Payload: {client_uuid, client_cert_sha256}.
    inline constexpr std::string_view kAuthorize = "authorize";
    /// Host pushes a revocation notification. Payload: {client_uuid}.
    /// Best-effort; the next authorize RPC is authoritative.
    inline constexpr std::string_view kRevoke = "revoke";
    /// Host asks the companion to issue a pairing grant. Payload:
    /// {client_uuid, client_cert_pem, client_cert_sha256,
    ///  host_cert_sha256, client_nonce}. The companion replies with the
    /// exact fields of the bootstrap response envelope.
    inline constexpr std::string_view kIssueGrant = "issue_grant";
  }  // namespace op

  /// Stable error codes returned in the `error` field of failed responses.
  /// Wire-compatible; do not rename. Companions pattern-match on these.
  namespace error {
    inline constexpr std::string_view kNone = "";
    inline constexpr std::string_view kUnsupported = "unsupported";
    inline constexpr std::string_view kBridgeAbsent = "bridge_absent";
    inline constexpr std::string_view kBadRequest = "bad_request";
    inline constexpr std::string_view kUnpaired = "unpaired";
    inline constexpr std::string_view kRevoked = "revoked";
    inline constexpr std::string_view kRateLimited = "rate_limited";
    inline constexpr std::string_view kInternal = "internal";
    inline constexpr std::string_view kTimeout = "timeout";
    inline constexpr std::string_view kDisconnected = "disconnected";
    inline constexpr std::string_view kProto = "proto";
    inline constexpr std::string_view kPathMismatch = "path_mismatch";
    inline constexpr std::string_view kSidMismatch = "sid_mismatch";
    inline constexpr std::string_view kSessionMismatch = "session_mismatch";
  }  // namespace error

  // -------- Frame parsing / writing (portable, byte-order safe) ------------

  /// Result of decoding a single length-prefixed frame from a byte stream.
  struct frame_t {
    std::uint32_t length = 0;
    std::vector<std::uint8_t> payload;
    /// True when the frame was rejected (length oversize, truncated).
    bool truncated = false;
  };

  /// Append a single frame to `out`. Returns false when `payload` exceeds
  /// `kMaxFrameBytes` (we never silently truncate).
  bool write_frame(std::vector<std::uint8_t> &out, std::string_view payload);

  /// Try to consume one full frame from `buffer`. On success returns the
  /// frame and shrinks `buffer` by the consumed prefix. On incomplete data
  /// returns std::nullopt without modifying `buffer`. On a length-prefix
  /// larger than `kMaxFrameBytes` clears `buffer` (defence against a peer
  /// that sends a malicious oversized length and then dribbles bytes).
  std::optional<frame_t> try_read_frame(std::vector<std::uint8_t> &buffer);

  // -------- JSON envelope parsing ------------------------------------------

  /// Decoded inbound JSON envelope (request). Only the fields Vibeshine
  /// consumes are exposed; everything else is dropped on the floor.
  struct inbound_envelope_t {
    std::uint32_t version = 0;
    std::string id;  ///< Caller-chosen id; echoed in the response.
    std::string op;  ///< Operation name.
    /// Free-form payload. Companion validation rejects unknown ops in the
    /// transport layer; we only parse the well-known ones here.
    std::string payload_json;
  };

  /// Decoded outbound JSON envelope (response). The `ok` flag drives the
  /// `payload` vs `error` branch in the JSON wire shape.
  struct outbound_envelope_t {
    std::uint32_t version = 0;
    std::string id;
    bool ok = false;
    std::string payload_json;
    std::string error;
  };

  /// Parse a single frame payload as a request envelope. The payload must
  /// contain at least the schema, id, op fields. Returns std::nullopt when
  /// the JSON cannot be decoded or a required field is missing/malformed.
  std::optional<inbound_envelope_t> parse_request(std::string_view frame);

  /// Parse a single frame payload as a response envelope. The payload must
  /// contain at least the schema, id, and ok fields; carries either an
  /// error or a payload (or both, but error wins for failure semantics).
  /// Use this for host->companion responses (no `op`).
  std::optional<outbound_envelope_t> parse_response(std::string_view frame);

  /// Encode an `ok` response. Always emits a fully-formed JSON object.
  std::string encode_ok_response(std::uint32_t version, std::string_view id, std::string_view payload_json);

  /// Encode an error response. The companion treats `error` as a stable
  /// token from the `error` namespace above.
  std::string encode_error_response(std::uint32_t version, std::string_view id, std::string_view error);

  /// Encode a revoke notification. Not a request: `id` may be empty.
  std::string encode_revoke_notification(std::uint32_t version, std::string_view client_uuid);

  // -------- High-level RPC envelope helpers --------------------------------

  /// Wire-format authorize request from companion to host.
  struct authorize_request_t {
    std::string client_uuid;
    std::string client_cert_sha256;  ///< lowercase hex, 64 chars
  };

  /// Wire-format authorize response from host to companion.
  struct authorize_response_t {
    bool authorized = false;
  };

  /// Decode `{client_uuid, client_cert_sha256}` from a payload blob. UUID
  /// must be present and printable; cert sha must be exactly 64 lowercase
  /// hex chars. Returns std::nullopt otherwise.
  std::optional<authorize_request_t> parse_authorize_request(std::string_view payload);

  /// Encode `{authorized}` to send back to the companion.
  std::string encode_authorize_response(const authorize_response_t &response);

  /// Wire-format issue_grant request from host to companion (sent after the
  /// HTTPS /api/vr/bootstrap handler authorises the bootstrap).
  struct issue_grant_request_t {
    std::string client_uuid;
    std::string client_cert_pem;  ///< PEM-encoded client cert
    std::string client_cert_sha256;  ///< lowercase hex, 64 chars
    std::string host_cert_sha256;  ///< lowercase hex, 64 chars
    std::string client_nonce;  ///< exactly 64 lowercase hex chars
  };

  /// Wire-format issue_grant response from companion to host. Each field is
  /// bounded; the host validates them all before relaying to the HTTPS
  /// caller.
  struct issue_grant_response_t {
    std::string grant;
    std::int64_t expires_unix = 0;
    std::string client_nonce;
    std::string client_uuid;
    std::string host_cert_sha256;
    std::string companion_cert_sha256;
    std::uint16_t port = 0;
  };

  /// Encode an issue_grant request payload.
  std::string encode_issue_grant_request(const issue_grant_request_t &request);

  /// Decode an issue_grant response payload. Returns std::nullopt when any
  /// field is missing or fails its bounded-format check.
  std::optional<issue_grant_response_t> parse_issue_grant_response(std::string_view payload);

  // -------- Field validation helpers (portable) ----------------------------

  /// True when value is non-empty, exactly 64 chars, and all lowercase hex.
  bool is_lower_hex_64(std::string_view value);

  /// True when value is a valid UUID string (8-4-4-4-12 hex).
  bool is_uuid_string(std::string_view value);

  /// True when value is a syntactically valid PEM (BEGIN/END CERTIFICATE
  /// block, base64 body). Does not parse the ASN.1.
  bool is_pem_certificate(std::string_view value);

}  // namespace vr_pairing_bridge
