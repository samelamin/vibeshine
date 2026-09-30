// Actual production Asio transport, with only paired-client DB authority faked.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <functional>
#include <sddl.h>
#include <atomic>
#include <chrono>
#include <future>
#include <filesystem>
#include <thread>
#include <nlohmann/json.hpp>
#include "tests/tests_common.h"
#include "src/platform/common/vr_pairing_bridge.h"
#include "src/utility.h"

using namespace std::chrono_literals;
namespace wire = ::vr_pairing_bridge;
namespace host_bridge = platf::vr_pairing_bridge;
using json = nlohmann::json;
static std::atomic<unsigned> authority_calls {0};
static const std::string uuid = "aabbccdd-1122-3344-5566-778899aabbcc";
static const std::string sha(64, 'a');
namespace nvhttp::vr_pairing_bridge {
  bool authorize_client_locked(const std::string &id, const std::string &fingerprint) {
    ++authority_calls;
    return id == uuid && fingerprint == sha;
  }
}
namespace {
  bool until(const std::function<bool()> &predicate, std::chrono::milliseconds duration) {
    const auto end = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < end) {
      if (predicate()) return true;
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }
  struct peer_t {
    std::atomic<bool> stop {false}, stall {false}, failed {false};
    std::atomic<unsigned> connections {0};
    std::atomic<DWORD> last_error {ERROR_SUCCESS};
    std::wstring name;
    std::thread thread;
    explicit peer_t(DWORD session): name(L"\\\\.\\pipe\\VibertemisVRBridge-"+std::to_wstring(session)), thread([this]{ run(); }) {}
    ~peer_t() { stop = true; thread.join(); }
    bool transfer(HANDLE pipe, uint8_t *data, size_t size, bool write) {
      const auto deadline = std::chrono::steady_clock::now()+8s;
      size_t offset=0;
      while (!stop && offset<size && std::chrono::steady_clock::now()<deadline) {
        DWORD done=0;
        // Server handle is deliberately synchronous PIPE_NOWAIT: no stack
        // OVERLAPPED or indefinite kernel waits in the test peer.
        BOOL ok = write ? WriteFile(pipe,data+offset,static_cast<DWORD>(std::min(size-offset,size_t(7))),&done,nullptr)
                        : ReadFile(pipe,data+offset,static_cast<DWORD>(size-offset),&done,nullptr);
        if (!ok && GetLastError()!=ERROR_NO_DATA) return false;
        offset+=done;
        if (!done) std::this_thread::sleep_for(1ms);
      }
      return offset==size;
    }
    bool send(HANDLE pipe,const json &message) {
      std::vector<uint8_t> frame;
      if(!wire::write_frame(frame,message.dump()))return false;
      return transfer(pipe,frame.data(),frame.size(),true);
    }
    void run() {
      try {
        while(!stop) {
          HANDLE pipe=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
              PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,nullptr);
          if(pipe==INVALID_HANDLE_VALUE){last_error=GetLastError();failed=true;return;}
          auto close=util::fail_guard([&]{DisconnectNamedPipe(pipe);CloseHandle(pipe);});
          bool abandoned=false;
          bool connected=until([&]{
            if(stop)return true;
            // PIPE_NOWAIT success means available, not connected.
            if(ConnectNamedPipe(pipe,nullptr))return false;
            const DWORD error=GetLastError();
            last_error=error;
            // A rejected client may close before the peer observes CONNECTED.
            // Recreate this instance immediately; otherwise it stays unavailable.
            if(error==ERROR_NO_DATA || error==ERROR_BROKEN_PIPE){abandoned=true;return true;}
            return error==ERROR_PIPE_CONNECTED;
          },8s);
          if(!connected || stop || abandoned)continue;
          ++connections;
          json held;
          while(!stop) {
            uint8_t prefix[4];
            if(!transfer(pipe,prefix,4,false))break;
            uint32_t length=uint32_t(prefix[0])|(uint32_t(prefix[1])<<8)|(uint32_t(prefix[2])<<16)|(uint32_t(prefix[3])<<24);
            if(!length||length>wire::kMaxFrameBytes){failed=true;return;}
            std::vector<uint8_t> data(length);
            if(!transfer(pipe,data.data(),data.size(),false))break;
            auto message=json::parse(data);
            if(message.contains("op")) {
              std::string op=message["op"];
              if(op=="ping") {
                if(!send(pipe,{{"v",1},{"id",message["id"]},{"ok",true},{"payload",json::object()}}))break;
              } else if(op=="issue_grant" && !stall) {
                const auto &p=message["payload"];
                held={{"v",1},{"id",message["id"]},{"ok",true},{"payload",{
                  {"schema",1},{"grant",std::string(64,'b')},{"expires_unix",2000000000},
                  {"client_nonce",p["client_nonce"]},{"client_uuid",p["client_uuid"]},
                  {"host_cert_sha256",p["host_cert_sha256"]},{"companion_cert_sha256",sha},{"port",28540}}}};
                // A companion authorization while the host's RPC is pending
                // proves that the real reader is duplex, not request-locked.
                if(!send(pipe,{{"v",1},{"id","peer-auth"},{"op","authorize"},{"payload",{{"client_uuid",uuid},{"client_cert_sha256",sha}}}}))break;
              }
            } else if(message.value("id","")=="peer-auth") {
              if(!message.value("ok",false)||!message["payload"].value("authorized",false)){failed=true;return;}
              if(!send(pipe,held))break;
            }
          }
        }
      } catch(...) { failed=true; }
    }
  };
}

TEST(VrPairingBridgeIpc, ActualTransportRejectsWrongPeerThenHandlesDuplexDeadlineAndShutdown) {
  DWORD session=0;
  ASSERT_TRUE(ProcessIdToSessionId(GetCurrentProcessId(),&session));
  ASSERT_EQ(session,WTSGetActiveConsoleSessionId()) << "Transport smoke requires the runner's active console session";
  const wchar_t *key_name=L"SOFTWARE\\Vibertemis\\VRBridge";
  HKEY existing=nullptr;
  ASSERT_EQ(RegOpenKeyExW(HKEY_LOCAL_MACHINE,key_name,0,KEY_READ|KEY_WOW64_64KEY,&existing),ERROR_FILE_NOT_FOUND)
      << "Refusing to modify a pre-existing bridge registration";
  HKEY key=nullptr;
  ASSERT_EQ(RegCreateKeyExW(HKEY_LOCAL_MACHINE,key_name,0,nullptr,0,KEY_ALL_ACCESS|KEY_WOW64_64KEY,nullptr,&key,nullptr),ERROR_SUCCESS);
  auto cleanup=util::fail_guard([&]{host_bridge::shutdown_bridge();RegCloseKey(key);RegDeleteKeyExW(HKEY_LOCAL_MACHINE,key_name,KEY_WOW64_64KEY,0);});
  auto set=[&](const wchar_t *name,const std::wstring &value){
    return RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE *>(value.c_str()),static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)));
  };
  wchar_t image[32768];ASSERT_GT(GetModuleFileNameW(nullptr,image,32768),0u);
  HANDLE token=nullptr;ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
  auto close_token=util::fail_guard([&]{CloseHandle(token);});
  DWORD bytes=0;GetTokenInformation(token,TokenUser,nullptr,0,&bytes);
  std::vector<uint8_t> info(bytes);ASSERT_TRUE(GetTokenInformation(token,TokenUser,info.data(),bytes,&bytes));
  LPWSTR sid=nullptr;ASSERT_TRUE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(info.data())->User.Sid,&sid));
  auto free_sid=util::fail_guard([&]{LocalFree(sid);});
  ASSERT_EQ(set(L"UserSid",sid),ERROR_SUCCESS);
  ASSERT_EQ(set(L"SunshinePath",image),ERROR_SUCCESS);
  wchar_t system[32768];ASSERT_GT(GetSystemDirectoryW(system,32768),0u);
  ASSERT_EQ(set(L"CompanionPath",std::wstring(system)+L"\\cmd.exe"),ERROR_SUCCESS);
  peer_t peer(session);
  EXPECT_FALSE(until([]{return host_bridge::get_capabilities().bridge_ready;},1500ms));
  ASSERT_EQ(set(L"CompanionPath",image),ERROR_SUCCESS);
  ASSERT_TRUE(until([]{return host_bridge::get_capabilities().bridge_ready;},5s))
      << "connections=" << peer.connections << " peer_failed=" << peer.failed << " last_pipe_error=" << peer.last_error;
  wire::issue_grant_request_t request {uuid,"fixture certificate",sha,sha,std::string(64,'c')};
  auto grant=host_bridge::request_issue_grant(request);
  ASSERT_TRUE(grant.has_value());
  EXPECT_EQ(grant->client_uuid,uuid);
  EXPECT_EQ(authority_calls.load(),1u);
  EXPECT_FALSE(peer.failed);
  peer.stall=true;
  const auto previous_connections=peer.connections.load();
  const auto begin=std::chrono::steady_clock::now();
  EXPECT_FALSE(host_bridge::request_issue_grant(request).has_value());
  EXPECT_GE(std::chrono::steady_clock::now()-begin,4s);
  EXPECT_LT(std::chrono::steady_clock::now()-begin,7s);
  ASSERT_TRUE(until([&]{return peer.connections.load()>previous_connections && host_bridge::get_capabilities().bridge_ready;},5s));
  auto waiting=std::async(std::launch::async,[&]{return host_bridge::request_issue_grant(request);});
  std::this_thread::sleep_for(100ms);
  const auto stop_begin=std::chrono::steady_clock::now();
  host_bridge::shutdown_bridge();
  EXPECT_LT(std::chrono::steady_clock::now()-stop_begin,1s);
  ASSERT_EQ(waiting.wait_for(1s),std::future_status::ready);
  EXPECT_FALSE(waiting.get().has_value());
  EXPECT_FALSE(peer.failed);
}
