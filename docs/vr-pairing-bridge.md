#Vibeshine first - party VR pairing bridge

The Vibeshine half of the first - party VR pairing bridge connects Sunshine to a per - user companion that brokers the Android client's TLS pairing handshake. This document records the wire contract, the trust boundary, and the Windows runtime constraints.

                                                                                                                                                                                                                                This branch implements **only **the
                                                                                                                                                                                                                                Vibeshine(host)
side of the bridge.The
  companion implementation lives in its own repository;
the wire contract here
        is the binding contract between the two implementations.

      ##Topology

``` Android client-- -
      TLS / pinned-- >
    Companion(per - user, unsigned) |
  v
                          \\.\pipe\VibertemisVRBridge - <sessionid> |
  v Sunshine(Vibeshine host)
```

    The companion owns the named
    - pipe server.The host is the client and reconnects on failure with bounded backoff.The host NEVER impersonates the peer: the pipe is opened with `SECURITY_SQOS_PRESENT
  | SECURITY_IDENTIFICATION` and the host inspects the peer's TokenUser via identification-level
`ImpersonateNamedPipeClient`.The companion is the side that uses full
`ImpersonateNamedPipeClient` to verify `SunshinePath` against the host identity.

        ##Trust boundary(Agy adjudication)

        * The companion per
      - user process is **unsigned **;
we do not assume
      Authenticode on it.* `sunshinesvc::DuplicateTokenForSession` duplicates the LocalSystem token and
  only changes the session id,
  so a Sunshine host that entered the
    active console session as SYSTEM may legitimately own a LocalSystem
      identity.We therefore **never assume the host is the user **.
        *Registration values `UserSid`, `CompanionPath`, `SunshinePath` under
  `HKLM\SOFTWARE\Vibertemis\VRBridge` are written by the **elevated Windows installer **(the VR helper setup helper).They are canonical absolute paths.Runtime does not write them.* The malicious admin / SYSTEM and same - user malware threat models already hold the private keys needed to forge the Sunshine TLS identity,
  so we do not gain anything by trying to lock them out further.We * *do * *protect other users on the host and remote attackers from impersonating the companion.* The host validates the pipe SERVER(companion)
on every connection:
  `GetNamedPipeServerProcessId` -> `QueryFullProcessImageNameW` must match
      the registered `CompanionPath` exactly(case -insensitive canonical path comparison), `ImpersonateNamedPipeClient` (identification - only) reads
  `TokenUser` which must equal `UserSid`,
  and the peer's session id must equal both the active console session id and the host's own session id.
    *The host only brokers the `issue_grant` RPC: it never persists the grant,
  never logs it, and only relays the validated bounded response fields.*The fresh authorize RPC is authoritative.A revoke notification is best effort;
if it {
  is missed the next authorize still denies the disabled
        record.

      ##Wire contract

        Wire schema version: **1 *
      *.

       Frame : 4 -
    byte little - endian uint32 length prefix + JSON payload(max 65536 bytes per frame, defended at both ends).

                                                Channel messages:

```jsonc
      // Companion -> Host request
      {
        "v": 1,
        "id": "<random caller-chosen id; echoed in response>",
        "op": "authorize",
        "payload": {"client_uuid": "<uuid>", "client_cert_sha256": "<64 lower-hex>"}
      }

  // Host -> Companion response
  {
    "v" : 1,
      "id": "<echo>", "ok": true, "payload": {
      "authorized": true | false
    }
  }
}

// Host -> Companion revoke notification (best effort)
{
  "v" : 1,
    "id": "", "op": "revoke", "payload": {"client_uuid": "<uuid>"}
}

// Host -> Companion issue_grant request (broker-only; never persisted)
{
  "v" : 1,
    "id": "<random caller-chosen id>", "op": "issue_grant", "payload": {
      "client_uuid": "<uuid>",
      "client_cert_pem": "<PEM>",
      "client_cert_sha256": "<64 lower-hex>",
      "host_cert_sha256": "<64 lower-hex>",
      "client_nonce": "<64 lower-hex>"
    }
}

// Companion -> Host issue_grant response
{
  "v" : 1,
    "id": "<echo>", "ok": true, "payload": {
      "grant": "<base64 string, 1..4096 chars>",
      "expires_unix": <int64>,
      "client_nonce": "<64 lower-hex>",
      "client_uuid": "<uuid>",
      "host_cert_sha256": "<64 lower-hex>",
      "companion_cert_sha256": "<64 lower-hex>",
      "port": 28540
    }
}

// Companion -> Host error response (matches `error::kFoo` token)
{
  "v": 1,
  "id": "<echo>",
  "ok": false,
  "error": "unsupported" | "bridge_absent" | "bad_request" |
    "unpaired" | "revoked" | "rate_limited" | "internal" |
    "timeout" | "disconnected" | "proto" |
    "path_mismatch" | "sid_mismatch" | "session_mismatch"
}
```

  The wire field names(`v`, `id`, `op`, `payload`, `ok`, `error `,
`client_uuid`, `client_cert_pem`, `client_cert_sha256`, `host_cert_sha256`,
`companion_cert_sha256`, `client_nonce`, `grant`, `expires_unix`, `port`,
`authorized`) are part of the contract.Renaming breaks the companion.

  ##HTTP API

  Both endpoints are added to the existing HTTPS server alongside the existing paired
  - client routes(`/ pair`, `/ unpair`, etc.).They require the same pinned TLS client cert chain as the rest of the HTTPS API.The fresh peer - cert validation is performed on every call: the TLS endpoint cache is explicitly **not **consulted.

                                                                                                                                                                                           ## # `GET
                                                                                                                                                 / api / vr / capabilities`

                                                                                                                                                 Response(always 200):

```json {
      "schema": 1,
      "bootstrap": 1,
      "bridge_ready": true,
      "error": ""
    }
```

`bridge_ready` is true only when the elevated installer registered the bridge triad under `HKLM\SOFTWARE\Vibertemis\VRBridge`,
the active console session exists,
and the host is currently executing inside that session.Anything else means `bridge_ready = false` and a populated `error `.

                                                                                                           ## # `POST
                                                                                                           / api / vr / bootstrap`

                                                                                                           Request body(max 16 KiB):

```json {"schema": 1, "client_nonce": "<64 lower-hex>"}
```

    Response body on success(200):

```json {
      "schema": 1,
      "grant": "<base64>",
      "expires_unix": <int64>,
      "client_nonce": "<64 lower-hex>",
      "client_uuid": "<uuid>",
      "host_cert_sha256": "<64 lower-hex>",
      "companion_cert_sha256": "<64 lower-hex>",
      "port": 28540
    }
```

    Status codes:

                                                                                                         | Code | Meaning | | -- -- --| -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --| | 200 | Success.Body matches the contract above.| | 400 | Bad request(malformed JSON, schema mismatch, malformed nonce).| | 401 | The presenting peer is not authorized(no live TLS handshake / unpaired / revoked).| | 413 | Body too large(> 16 KiB).| | 429 | Rate - limited(per - client 6 / minute, global 60 / minute).| | 502 | Companion rejected the `issue_grant` RPC.| | 503 | Bridge not ready(no registration, host not in active console session).|

                                                                                                         ##Implementation notes

                                                                                                             * The portable layer(`src / vr_pairing_bridge.{ h, cpp }`) is platform
                                                                                                           - neutral
                                                                                            and depends only on `nlohmann_json`.It defines the frame format,
                                                                            JSON envelope shape, error tokens, op names, and field validators.*The platform interface(`src / platform / common / vr_pairing_bridge.{ h, cpp }`) defines the cross - platform API surface.The non - Windows stub returns
  `bridge_ready = false` so the HTTPS handlers always respond with 503 outside Windows builds.* The Windows transport(`src / platform / windows / vr_pairing_bridge.cpp`) owns the named - pipe client(overlapped I / O), the reader thread, the pending RPC map, the revoke queue, and the registry reloader.*The HTTPS handlers in `src / nvhttp.cpp` consult a sidecar handshake map keyed by `SSL *` to obtain the live peer cert captured during the TLS handshake.A fresh re - derivation of the canonical DER identity + the global paired - clients resolver is performed under `client_mutex` so racing disable / unpair is observed.

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ##Unbundled TrueHDR limitation

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            This branch ships the RTX HDR SDR→HDR synthesis stubs but does not include the TrueHDR runtime.The preview CI workflow(`vr - pairing - ci.yml`) sets
`require_truehdr_runtime = false`.The MSI does * *not * *claim full feature parity with the unbundled TrueHDR release;
downstream consumers should
    document this.RTX HDR works as a no -
  op when the runtime DLL is absent.

    ##Workflow

`.github /
    workflows / vr -
  pairing - ci.yml` reuses the existing
`.github / workflows / ci - windows.yml` via `uses:` so the preview build uses the exact same Windows build matrix and dependency pins.The workflow is pinned to the fork owner(`samelamin / vibeshine`); it never publishes a release to
`Nonary/vibeshine`.

Inputs used:

* `require_signpath_signing=false` (preview never publishes a signed MSI)
* `require_truehdr_runtime=false` (preview does not bundle the runtime)
* `build_tests=true` (the VR bridge test target builds and runs)
* `build_only=true` (no SignPath submission)
* `release_artifact_retention_days=1` (preview artifacts live one day)

## Unresolved Windows runtime limits

This branch was authored on a Linux CI host and reviewed by codex for
contract/IO/security issues. The following Windows runtime limits remain:

1. **End-to-end Windows execution was not performed in this worktree.** The
   `src/platform/windows/vr_pairing_bridge.cpp` file was reviewed for
   syntax, namespace, and resource lifetime; it was not compiled or
   executed against a live `sunshinesvc` + companion. A real Windows CI
   build will reveal any compilation errors I missed.
2. **Windows IPC tests are wired up but not executed locally.** The
   portable test target (`test_fast_vr_pairing_bridge_protocol`) runs on
   every platform and exercises frame/JSON/validators/contract invariants.
   The Windows-only IPC test target
   (`test_component_vr_pairing_bridge_ipc`) drives a fake companion against
   real named pipes (fragmented frames, concurrent responses, stalled
   reads, disconnect mid-RPC, peer path/SID/session authority, host does
   not adopt peer identity) and runs under `BUILD_TESTS=ON` in the Windows
   preview CI workflow. End-to-end Windows execution still depends on the
   real CI runner.
3. **Authenticode on the companion is not assumed.** If the user's threat
   model demands Authenticode, that has to be added to `verify_peer` and is
   not currently part of the contract.
4. **The companion is per-user and unsigned.** Any code-signing policy
   for the companion is out of scope for this branch. The preview workflow
   does NOT claim Authenticode parity.
6. **No automatic deploy.** The preview workflow never pushes artifacts
   anywhere except the fork-owned CI artifacts, which expire after one day.

## What is intentionally NOT changed

* The existing TLS verification pipeline, `cert_chain`, and the
  `tls_client_identity_by_endpoint` cache remain untouched. The VR bridge
  has its own handshake sidecar map keyed by `SSL*`;
we do **not **weaken or shortcut the existing endpoint cache.
                          * `setBitrate`, `/ api / abr / capabilities`, `/ pyrowave - bandwidth - probe`,
  and every other existing HTTPS route is untouched.
        * `sunshinesvc` (the elevated helper service) is untouched.The adjudication noted that `sunshinesvc::DuplicateTokenForSession` duplicates LocalSystem;
we accept that fact but we do not write any state from sunshinesvc
  ourselves.

## Takeover transport review — 2026-09-30

Agy Gemini 3.1 Pro (High) reviewed the transport correction plan. The host now uses Boost.Asio stream_handle with one I/O worker, bounded submissions/pending requests, per-operation deadlines, ownership through cancelled completions, and an explicit authenticated ping before advertising readiness. Registration loss/session changes close the generation.

Adjudication: retain the HTTP caller absolute deadline as well as the I/O deadline: shared promise ownership makes abandonment safe and bounds callers if the worker stalls. Unsolicited companion authorize RPCs are required; therefore incoming partial frames use a five-second timer rather than rejecting traffic when no host RPC is pending. Host startup discovers the local bridge without starting SteamVR.

This branch is a draft for Windows CI, not a release or final sign-off. Real Windows transport and final Agy review remain required.

Agy implementation review found no concrete transport lifetime/authentication blocker after correction. Source verification resolves its conditional comments: `util::FailGuard` runs unless disabled; `sunshinesvc.cpp` creates Sunshine in the active console session with a duplicated SYSTEM token; Windows uses the current MSYS OpenSSL dependency. Initial Windows CI caught the standalone test source being compiled twice (once without its macros); CMake now compiles only its including runner. Actual host/pipe tests remain the release gate.
