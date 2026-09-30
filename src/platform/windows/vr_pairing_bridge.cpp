// One Asio thread owns each pipe generation and all pending RPCs. Captured
// shared owners keep buffers and handles alive through cancelled completions.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <boost/asio.hpp>
#include <boost/asio/windows/stream_handle.hpp>
#include <array>
#include <atomic>
#include <deque>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include "src/platform/common/vr_pairing_bridge.h"
#include "src/nvhttp.h"
#include "src/logging.h"
#include "src/utility.h"

namespace platf::vr_pairing_bridge {
  namespace {
    namespace asio = boost::asio;
    namespace wire = ::vr_pairing_bridge;
    using json = nlohmann::json;
    using reply_t = std::optional<wire::outbound_envelope_t>;
    using clock_t = std::chrono::steady_clock;
    struct registration_t {
      std::wstring user_sid, companion_path, sunshine_path;
      DWORD session_id = 0;
      bool operator==(const registration_t &) const = default;
    };
    std::wstring registry_read_string(HKEY key, const wchar_t *value_name) {
      DWORD type = 0;
      DWORD byte_count = 0;
      LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &byte_count);
      if (rc != ERROR_SUCCESS || type != REG_SZ || byte_count > 65536 || byte_count % sizeof(wchar_t) != 0) {
        return {};
      }
      std::wstring out;
      out.resize(byte_count / sizeof(wchar_t) + 1);
      DWORD actual = static_cast<DWORD>(out.size() * sizeof(wchar_t));
      rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(out.data()), &actual);
      if (rc != ERROR_SUCCESS) {
        return {};
      }
      std::size_t chars = actual / sizeof(wchar_t);
      if (chars > 0 && out[chars - 1] == L'\0') {
        --chars;
      }
      out.resize(chars);
      return out;
    }

    bool load_registration(registration_t &out) {
      HKEY key = nullptr;
      const std::wstring reg_path = L"SOFTWARE\\Vibertemis\\VRBridge";
      LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key);
      if (rc != ERROR_SUCCESS) {
        return false;
      }
      auto close_guard = util::fail_guard([&key]() {
        if (key) {
          RegCloseKey(key);
        }
      });

      const auto user_sid = registry_read_string(key, L"UserSid");
      const auto companion = registry_read_string(key, L"CompanionPath");
      const auto sunshine = registry_read_string(key, L"SunshinePath");
      if (user_sid.empty() || companion.empty() || sunshine.empty()) {
        return false;
      }
      std::error_code ec;
      auto companion_canon = std::filesystem::canonical(companion, ec);
      if (ec) {
        return false;
      }
      auto sunshine_canon = std::filesystem::canonical(sunshine, ec);
      if (ec) {
        return false;
      }
      if (companion_canon.empty() || sunshine_canon.empty()) {
        return false;
      }
      PSID psid = nullptr;
      if (!ConvertStringSidToSidW(user_sid.c_str(), &psid)) {
        return false;
      }
      LPWSTR roundtrip = nullptr;
      if (!ConvertSidToStringSidW(psid, &roundtrip)) {
        LocalFree(psid);
        return false;
      }
      std::wstring normalized_sid = roundtrip ? roundtrip : L"";
      LocalFree(roundtrip);
      LocalFree(psid);
      if (normalized_sid.empty()) {
        return false;
      }
      DWORD session_id = WTSGetActiveConsoleSessionId();
      if (session_id == 0xFFFFFFFFu) {
        return false;
      }
      out.user_sid = std::move(normalized_sid);
      out.companion_path = std::wstring {companion_canon.native()};
      out.sunshine_path = std::wstring {sunshine_canon.native()};
      out.session_id = session_id;
      return true;
    }

    // ----------------------------------------------------------------------
    // Pipe connection helpers
    // ----------------------------------------------------------------------

    std::wstring make_pipe_name(DWORD session_id) {
      return L"\\\\.\\pipe\\VibertemisVRBridge-" + std::to_wstring(session_id);
    }

    bool path_equals_case_insensitive(const std::wstring &a, const std::wstring &b) {
      return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
    }

    /// Returns true when `path` resolves (canonical absolute) to the same
    /// canonical absolute path as `registered`.
    bool canonical_path_matches(const std::wstring &path, const std::wstring &registered) {
      std::error_code ec;
      auto canon = std::filesystem::canonical(path, ec);
      if (ec) {
        return false;
      }
      return path_equals_case_insensitive(canon.native(), registered);
    }

    bool verify_peer_pipe(const registration_t &reg, HANDLE pipe, DWORD expected_session) {
      ULONG server_pid = 0;
      if (!GetNamedPipeServerProcessId(pipe, &server_pid) || server_pid == 0) {
        return false;
      }
      HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(server_pid));
      if (!proc) {
        return false;
      }
      auto proc_guard = util::fail_guard([&proc]() {
        if (proc) {
          CloseHandle(proc);
        }
      });
      // 1) Canonical image path must match the registered CompanionPath.
      wchar_t image_path[32768];
      DWORD image_path_size = 32768;
      if (!QueryFullProcessImageNameW(proc, 0, image_path, &image_path_size)) {
        return false;
      }
      if (!canonical_path_matches(std::wstring {image_path, image_path_size}, reg.companion_path)) {
        BOOST_LOG(debug) << "vr_pairing_bridge: companion image mismatch";
        return false;
      }
      // 2) Open the peer process's primary token (NOT via thread
      //    impersonation). This is a process-handle query; the host does
      //    not adopt the peer's identity.
      HANDLE peer_token = nullptr;
      if (!OpenProcessToken(proc, TOKEN_QUERY, &peer_token)) {
        return false;
      }
      auto token_guard = util::fail_guard([&peer_token]() {
        if (peer_token) {
          CloseHandle(peer_token);
        }
      });
      DWORD needed = 0;
      GetTokenInformation(peer_token, TokenUser, nullptr, 0, &needed);
      if (needed == 0) {
        return false;
      }
      std::vector<std::uint8_t> buf(needed);
      if (!GetTokenInformation(peer_token, TokenUser, buf.data(), needed, &needed)) {
        return false;
      }
      auto *tu = reinterpret_cast<TOKEN_USER *>(buf.data());
      if (!tu || !tu->User.Sid) {
        return false;
      }
      LPWSTR sid_str = nullptr;
      if (!ConvertSidToStringSidW(tu->User.Sid, &sid_str)) {
        return false;
      }
      auto sid_guard = util::fail_guard([&sid_str]() {
        if (sid_str) {
          LocalFree(sid_str);
        }
      });
      if (!path_equals_case_insensitive(sid_str ? sid_str : L"", reg.user_sid)) {
        BOOST_LOG(debug) << "vr_pairing_bridge: peer SID mismatch";
        return false;
      }
      // 3) Peer session id must equal both the registered session and our
      //    own session.
      DWORD peer_session = 0xFFFFFFFFu;
      if (!ProcessIdToSessionId(static_cast<DWORD>(server_pid), &peer_session)) {
        return false;
      }
      if (peer_session != reg.session_id || peer_session != expected_session) {
        BOOST_LOG(debug) << "vr_pairing_bridge: peer session mismatch (peer="
                         << peer_session << ", reg=" << reg.session_id
                         << ", host=" << expected_session << ")";
        return false;
      }
      return true;
    }

    HANDLE connect_pipe_with_sqos(const std::wstring &name) {
      SECURITY_ATTRIBUTES sa {};
      sa.nLength = sizeof(sa);
      sa.bInheritHandle = FALSE;
      return CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, &sa, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED, nullptr);
    }


    struct pending_t {
      asio::steady_timer timer;
      std::function<void(reply_t)> complete;
      pending_t(asio::io_context &io, std::function<void(reply_t)> fn): timer(io), complete(std::move(fn)) {}
    };
    struct connection_t {
      asio::windows::stream_handle pipe;
      asio::steady_timer frame_timer, write_timer;
      registration_t registration;
      std::array<uint8_t, 4> header {};
      std::vector<uint8_t> body;
      std::deque<std::shared_ptr<std::vector<uint8_t>>> writes;
      std::unordered_map<std::string, std::shared_ptr<pending_t>> pending;
      bool closed = false;
      connection_t(asio::io_context &io, HANDLE handle, registration_t reg): pipe(io, handle), frame_timer(io), write_timer(io), registration(std::move(reg)) {}
    };

    class transport_t {
      asio::io_context io;
      asio::executor_work_guard<asio::io_context::executor_type> work {asio::make_work_guard(io)};
      asio::steady_timer reconnect {io};
      std::shared_ptr<connection_t> current;
      std::thread worker;
      std::mutex lifecycle;
      bool started = false, stopping = false;
      uint64_t next_id = 0;
      std::atomic<bool> ready {false};
      // Limits posted jobs as well as the worker's pending map.
      std::atomic<unsigned> submissions {0};

      void close(std::shared_ptr<connection_t> c) {
        if (!c || c->closed) return;
        c->closed = true;
        if (current == c) { ready = false; current.reset(); }
        boost::system::error_code ignored;
        c->frame_timer.cancel();
        c->write_timer.cancel();
        c->pipe.cancel(ignored);
        c->pipe.close(ignored);
        auto pending = std::move(c->pending);
        for (auto &[id, entry] : pending) { entry->timer.cancel(); entry->complete(std::nullopt); }
        // In-flight writes capture their own buffer; queued buffers can go.
        c->writes.clear();
      }
      void write_next(const std::shared_ptr<connection_t> &c) {
        if (c->closed || c->writes.empty()) return;
        auto bytes = c->writes.front();
        c->write_timer.expires_after(wire::kDefaultRpcDeadline);
        c->write_timer.async_wait([this,c](auto ec) { if (!ec) close(c); });
        asio::async_write(c->pipe, asio::buffer(*bytes), [this,c,bytes](auto ec, size_t) {
          if (c->closed) return;
          if (ec) { close(c); return; }
          c->write_timer.cancel();
          c->writes.pop_front(); write_next(c);
        });
      }
      bool send(const std::shared_ptr<connection_t> &c, const std::string &message) {
        if (c->closed || c->writes.size() >= 64) { close(c); return false; }
        auto bytes = std::make_shared<std::vector<uint8_t>>();
        if (!wire::write_frame(*bytes, message)) { close(c); return false; }
        const bool idle = c->writes.empty();
        c->writes.push_back(bytes);
        if (idle) write_next(c);
        return true;
      }
      void rpc(const std::shared_ptr<connection_t> &c, std::string op, json payload,
               clock_t::time_point deadline, std::function<void(reply_t)> complete) {
        if (!c || c->closed || c->pending.size() >= wire::kMaxOutstandingRpcs || clock_t::now() >= deadline) {
          complete(std::nullopt); return;
        }
        auto id = std::to_string(++next_id);
        auto entry = std::make_shared<pending_t>(io, std::move(complete));
        c->pending.emplace(id, entry);
        entry->timer.expires_at(deadline);
        entry->timer.async_wait([this,c,entry](auto ec) { if (!ec) close(c); });
        send(c, json{{"v",1},{"id",id},{"op",op},{"payload",payload}}.dump());
      }
      void dispatch(const std::shared_ptr<connection_t> &c) {
        const std::string_view body(reinterpret_cast<const char *>(c->body.data()), c->body.size());
        auto request = wire::parse_request(body);
        if (request) {
          auto auth = wire::parse_authorize_request(request->payload_json);
          if (request->version != 1 || request->op != wire::op::kAuthorize || !auth) { close(c); return; }
          const bool allowed = nvhttp::vr_pairing_bridge::authorize_client_locked(auth->client_uuid, auth->client_cert_sha256);
          send(c, wire::encode_ok_response(1, request->id, wire::encode_authorize_response({allowed})));
          return;
        }
        auto response = wire::parse_response(body);
        if (!response || response->version != 1) { close(c); return; }
        auto found = c->pending.find(response->id);
        if (found == c->pending.end()) { close(c); return; }
        auto entry = found->second;
        c->pending.erase(found);
        entry->timer.cancel();
        entry->complete(std::move(response));
      }
      void read_header(const std::shared_ptr<connection_t> &c) {
        if (c->closed) return;
        // Wait indefinitely for the first byte; a partial frame has a fixed
        // 5s deadline. authorize is allowed even with no host request pending.
        asio::async_read(c->pipe, asio::buffer(c->header.data(),1), [this,c](auto ec, size_t) {
          if (c->closed) return;
          if (ec) { close(c); return; }
          c->frame_timer.expires_after(wire::kDefaultRpcDeadline);
          c->frame_timer.async_wait([this,c](auto err) { if (!err) close(c); });
          asio::async_read(c->pipe, asio::buffer(c->header.data()+1,3), [this,c](auto error, size_t) {
            if (c->closed) return;
            if (error) { close(c); return; }
            uint32_t size = uint32_t(c->header[0]) | (uint32_t(c->header[1])<<8) | (uint32_t(c->header[2])<<16) | (uint32_t(c->header[3])<<24);
            if (!size || size > wire::kMaxFrameBytes) { close(c); return; }
            c->body.resize(size);
            asio::async_read(c->pipe, asio::buffer(c->body), [this,c](auto failure, size_t) {
              if (c->closed) return;
              if (failure) { close(c); return; }
              c->frame_timer.cancel();
              try { dispatch(c); } catch (...) { close(c); }
              read_header(c);
            });
          });
        });
      }
      void tick() {
        registration_t reg;
        DWORD session = 0;
        const bool valid = load_registration(reg) && ProcessIdToSessionId(GetCurrentProcessId(), &session) && session == reg.session_id;
        if (current && (!valid || !(reg == current->registration))) close(current);
        if (!current && valid) {
          HANDLE handle = connect_pipe_with_sqos(make_pipe_name(session));
          if (handle != INVALID_HANDLE_VALUE) {
            if (!verify_peer_pipe(reg, handle, session)) CloseHandle(handle);
            else {
              try { current = std::make_shared<connection_t>(io, handle, reg); }
              catch (...) { CloseHandle(handle); }
              if (current) {
                auto c = current;
                read_header(c);
                rpc(c, "ping", json::object(), clock_t::now()+wire::kDefaultRpcDeadline,
                    [this,c](reply_t reply) { if (reply && reply->ok && current == c && !c->closed) ready = true; else close(c); });
              }
            }
          }
        }
        reconnect.expires_after(std::chrono::seconds(1));
        reconnect.async_wait([this](auto ec) { if (!ec) tick(); });
      }
      bool start_locked() {
        if (stopping) return false;
        if (!started) {
          started = true;
          asio::post(io, [this] { tick(); });
          worker = std::thread([this] { io.run(); });
        }
        return true;
      }
    public:
      ~transport_t() { stop(); }
      bool is_ready() {
        std::lock_guard lock(lifecycle);
        return start_locked() && ready.load();
      }
      std::future<reply_t> submit(std::string op, json payload) {
        auto promise = std::make_shared<std::promise<reply_t>>();
        auto future = promise->get_future();
        auto deadline = clock_t::now()+wire::kDefaultRpcDeadline;
        std::lock_guard lock(lifecycle);
        if (!start_locked() || !ready) {
          promise->set_value(std::nullopt); return future;
        }
        if (submissions.fetch_add(1) >= 32) {
          --submissions; promise->set_value(std::nullopt); return future;
        }
        asio::post(io, [this,op=std::move(op),payload=std::move(payload),promise,deadline] {
          rpc(current, op, payload, deadline, [this,promise](reply_t reply) { --submissions; promise->set_value(std::move(reply)); });
        });
        return future;
      }
      void stop() {
        std::unique_lock lock(lifecycle);
        if (stopping) return;
        stopping = true;
        if (!started) { work.reset(); return; }
        asio::post(io, [this] { reconnect.cancel(); close(current); work.reset(); });
        lock.unlock();
        if (worker.joinable()) worker.join();
      }
    };
    transport_t &transport() { static transport_t instance; return instance; }
  }
  capabilities_t get_capabilities() {
    const bool ready = transport().is_ready();
    return {1,1,ready,ready ? "" : "bridge_absent"};
  }
  std::optional<wire::issue_grant_response_t> request_issue_grant(const wire::issue_grant_request_t &request) {
    const auto deadline = clock_t::now()+wire::kDefaultRpcDeadline;
    auto future = transport().submit("issue_grant", json::parse(wire::encode_issue_grant_request(request)));
    // Shared promise ownership makes a caller timeout safe, including a stalled
    // io worker. Its timer still closes the generation when the worker resumes.
    if (future.wait_until(deadline) != std::future_status::ready) return std::nullopt;
    auto reply = future.get();
    if (!reply || !reply->ok) return std::nullopt;
    auto grant = wire::parse_issue_grant_response(reply->payload_json);
    if (!grant || grant->client_nonce != request.client_nonce || grant->client_uuid != request.client_uuid || grant->host_cert_sha256 != request.host_cert_sha256) return std::nullopt;
    return grant;
  }
  void enqueue_revoke(std::string_view uuid) {
    if (wire::is_uuid_string(uuid)) transport().submit("revoke", json{{"client_uuid",uuid}});
  }
  void shutdown_bridge() { transport().stop(); }
}
