# Vibeshine VR pairing bridge

The bridge lets Vibertemis reuse an existing GameStream pairing to enroll with the Windows VR companion. The Quest app selects its paired PC under **Setup VR**; the normal flow requires no pairing-file copy/paste.

## Setup and scope

Install the VR-enabled Vibeshine build and the matching Vibertemis VR Host Manager. Run **Setup VR** in the manager once. It checks the Windows runtime, registers the companion with an elevated helper, and prepares the driver and firewall. Hosting resumes after Windows sign-in when enabled. SteamVR starts on an authenticated VR connection, not when the host starts or a flat-screen client connects.

This bridge handles enrollment and authorization, not video transport or NAT traversal. Both the existing GameStream endpoint and the native VR companion/stream must be reachable. Forwarding GameStream ports alone is insufficient for tracked VR. Use a reachable local or VPN path for the native VR test.

## Trust boundary

Registration lives in 64-bit `HKLM\SOFTWARE\Vibertemis\VRBridge`: `UserSid`, `CompanionPath`, and `SunshinePath`. The elevated VR setup helper writes canonical paths and a protected ACL. Runtime processes only read registration.

The companion owns `\\.\pipe\VibertemisVRBridge-<active-session-id>`. The host opens it with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, validates the server process's canonical executable, primary-token SID, and session, and never impersonates the companion. The companion uses identification-level pipe impersonation to inspect the host token, then reverts before opening process handles. Sunshine can legitimately run as SYSTEM in the active console session: `sunshinesvc` duplicates the SYSTEM token into that session. Both sides reject a different session or changed registration.

The HTTPS handlers obtain the certificate from the live TLS connection, then resolve its current paired-client authority under `client_mutex`. A cached endpoint identity is insufficient. Duplicate, disabled, or removed clients fail authorization. The companion rechecks host authority at grant redemption and on each inherited-device request. Revoke delivery is best effort; fresh authorization remains authoritative.

The per-user companion and preview installers are unsigned. This trust model excludes a malicious administrator/SYSTEM or compromised paired user's private keys; it does not bypass certificate checks for remote callers.

## Wire contract

Schema version 1. Pipe frames contain a four-byte little-endian payload length followed by UTF-8 JSON, at most 65,536 payload bytes. Requests have `{v:1,id,op,payload}` with a nonempty ID. Responses echo the ID with `{v:1,id,ok:true,payload}` or `{v:1,id,ok:false,error}`.

Host to companion operations:

- `ping`: empty payload; successful response establishes readiness.
- `issue_grant`: `client_uuid`, `client_cert_pem`, `client_cert_sha256`, `host_cert_sha256`, and `client_nonce`.
- `revoke`: `client_uuid`; a bounded request with an ID, never a readiness dependency.

Companion to host operation:

- `authorize`: `client_uuid` and `client_cert_sha256`; response payload is `{authorized: true|false}` from the current paired-client database.

Successful grant payload: `schema:1`, `grant` (64 lowercase hex), `expires_unix`, echoed `client_nonce`, `client_uuid`, `host_cert_sha256`, `companion_cert_sha256`, and `port`. Certificate fingerprints and the nonce are 64 lowercase hex characters.

The Android client redeems the short-lived, single-use grant at the pinned companion HTTPS endpoint. Its RSA signature binds the nonce, grant, both certificate fingerprints, and client UUID. The companion persists a device credential only after fresh authorization; failed persistence leaves the prior pairing intact. Legacy manual pairing remains available under Advanced.

## GameStream HTTPS API

Both endpoints require an existing valid paired-client certificate:

- `GET /api/vr/capabilities`: `{schema:1,bootstrap:1,bridge_ready,error}`. Readiness requires a verified live pipe and successful ping.
- `POST /api/vr/bootstrap`: `{schema:1,client_nonce}`; body at most 16 KiB. Returns the grant payload above.

Bootstrap is limited to six requests per client per minute and sixty globally. Invalid input returns 400/413; revoked or unpaired clients return 401; throttling returns 429; an unavailable bridge returns 503; a failed companion grant returns 502. No grants or device tokens are logged.

## Transport and validation

One Boost.Asio worker owns each host pipe generation. Pending calls and submissions are bounded; RPCs, writes, and partial frames have five-second deadlines. The reader handles unsolicited authorization while an outgoing grant is pending. Cancellation retains buffers until completion, disconnect clears pending calls, and reconnection revalidates registration and peer identity.

`test_fast_vr_pairing_bridge_protocol` checks portable framing and validation. `test_component_vr_pairing_bridge_ipc` links the actual Windows transport against a real OS pipe peer and tests rejected peer paths, fragmented duplex traffic, deadlines, reconnect, and shutdown. It requires an elevated active-console Windows runner and refuses to overwrite existing bridge registration. The preview CI explicitly runs both after building. Physical Quest tracking, controllers, streaming quality, and remote-network behavior still require end-to-end hardware tests.

The fork-owned preview workflow reuses the Windows build and dependency pins. It bundles the pinned public TrueHDR runtime, sets `build_tests=true`, `build_only=true`, and `require_signpath_signing=false`. It does not publish to upstream or claim Authenticode parity. The update feed points to this fork so updates do not silently remove the VR bridge.

## Review record

Agy Gemini 3.1 Pro (High) reviewed the plan and implementation. Agreed corrections include one asynchronous I/O owner, bounded deadlines, explicit ping readiness, live TLS peer identity, and fresh paired-client authority. Keep both the HTTP caller deadline and the I/O deadline: shared promises make caller abandonment safe. Windows runtime CI and the final review remain release gates; a source review alone does not prove an end-to-end headset session.
