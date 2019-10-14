#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <Sddl.h>
#include <string>
#include <vector>
#include <nan.h>

#include "scopeguard.h"
#include "string_cast.h"

using namespace Nan;
using namespace v8;

static std::wstring strerror(DWORD errorno) {
  wchar_t *errmsg = nullptr;

  LCID lcid;
  GetLocaleInfoEx(L"en-US", LOCALE_RETURN_NUMBER | LOCALE_ILANGUAGE, reinterpret_cast<LPWSTR>(&lcid), sizeof(lcid));

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorno,
    lcid, (LPWSTR)&errmsg, 0, nullptr);

  if (errmsg) {
    for (int i = (wcslen(errmsg) - 1);
         (i >= 0) && ((errmsg[i] == '\n') || (errmsg[i] == '\r'));
         --i) {
      errmsg[i] = '\0';
    }

    return errmsg;
  }
  else {
    return L"Unknown error";
  }
}

Local<String> operator "" _n(const char *input, size_t) {
  return Nan::New(input).ToLocalChecked();
}

const char *translateCode(DWORD err) {
  switch (err) {
    // stupid fallthrough to avoid compiler warning
    case 0:
    default: return uv_err_name(uv_translate_sys_error(err));
  }
}

void setNodeErrorCode(v8::Local<v8::Context> context, v8::Local<v8::Object> err, DWORD errCode) {
  if (!err->Has(context, "code"_n).FromMaybe(false)) {
    err->Set(context, "code"_n, Nan::New(translateCode(errCode)).ToLocalChecked());
  }
}

inline v8::Local<v8::Value> WinApiException(
  DWORD lastError
  , const char *func = nullptr
  , const wchar_t *path = nullptr) {

  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  std::wstring errStr = strerror(lastError);
  std::string err = toMB(errStr.c_str(), CodePage::UTF8, errStr.size()) + " (" + std::to_string(lastError) + ")";
  std::string pathMB = toMB(path, CodePage::UTF8, wcslen(path));
  v8::Local<v8::Value> res = node::WinapiErrnoException(isolate, lastError, func, err.c_str(), pathMB.c_str());
  setNodeErrorCode(context, res->ToObject(Nan::GetCurrentContext()).ToLocalChecked(), lastError);
  return res;
}


class Access {
public:
  Access(Access &reference)
    : mAccess(reference.mAccess), mSid(reference.mSid)
  {
    reference.mOwner = false;
  }

  Access(ACCESS_MODE mode, const std::string &group, const std::string &permission) {
    mAccess.grfAccessMode = mode;
    mAccess.grfAccessPermissions = translatePermission(permission);
    mAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    mAccess.Trustee = makeTrustee(group);
  }

  Access &operator=(const Access&) = delete;

  ~Access() {
    if (mOwner && (mSid != nullptr)) {
      LocalFree(mSid);
    }
  }

  PEXPLICIT_ACCESSW operator*() {
    return &mAccess;
  }
private:
  WELL_KNOWN_SID_TYPE translateGroup(const std::string &group) {
    if (group == "everyone") {
      return WinAuthenticatedUserSid;
    }
    else if (group == "owner") {
      return WinCreatorOwnerSid;
    }
    else if (group == "group") {
      return WinBuiltinUsersSid;
    }
    else if (group == "guest") {
      return WinBuiltinGuestsSid;
    }
    else if (group == "administrator") {
      return WinBuiltinAdministratorsSid;
    } else {
      return WinNullSid;
    }
  }

  DWORD translatePermission(const std::string &rights) {
    static auto sPermissions = std::vector<std::pair<char, DWORD>>({
        std::make_pair('r', FILE_GENERIC_READ),
        std::make_pair('w', FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
                                FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE | DELETE),
        std::make_pair('x', FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
    });

    DWORD res = 0;
    for (auto kv : sPermissions) {
      if (rights.find_first_of(kv.first) != std::string::npos) {
        res |= kv.second;
      }
    }
    return res;
  }

  TRUSTEEW makeTrustee(const std::string &group) {
    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    // assume it's a known sid
    WELL_KNOWN_SID_TYPE knownSid = translateGroup(group);
    if (knownSid != WinNullSid) {
      mSid = LocalAlloc(LMEM_FIXED, sidSize);
      if (mSid == nullptr) {
        throw std::runtime_error("allocation error");
      }
      if (!CreateWellKnownSid(knownSid, nullptr, mSid, &sidSize)) {
        throw std::runtime_error(std::string("Failed to create sid from group \"") + group + "\": " + std::to_string(::GetLastError()));
      }
    } else {
      // no known sid, assume it's a stringified sid
      ConvertStringSidToSid(toWC(group.c_str(), CodePage::UTF8, group.size()).c_str(), &mSid);
    }

    TRUSTEEW res;
    res.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    res.pMultipleTrustee = nullptr;
    res.TrusteeForm = TRUSTEE_IS_SID;
    res.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    res.ptstrName = reinterpret_cast<LPWSTR>(mSid);
    return res;
  }
private:
  bool mOwner { true };
  EXPLICIT_ACCESSW mAccess;
  PSID mSid{nullptr};
};


class AccessFactory : public Nan::ObjectWrap {
public:
  static NAN_MODULE_INIT(Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
  }

  static NAN_METHOD(Grant) {
    if (info.Length() != 2) {
      Nan::ThrowError("Expected parameters (group, permission)");
      return;
    }

    v8::Local<v8::Function> cons = Nan::New(constructor());

    String::Utf8Value group(info.GetIsolate(), info[0]);
    String::Utf8Value permission(info.GetIsolate(), info[1]);

    const int argc = 3;
    v8::Local<v8::Value> argv[argc] = {
      Nan::New(GRANT_ACCESS),
      Nan::New(*group).ToLocalChecked(),
      Nan::New(*permission).ToLocalChecked(),
    };
    info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
  }

  static NAN_METHOD(Deny) {
    if (info.Length() != 2) {
      Nan::ThrowError("Expected parameters (group, permission)");
      return;
    }

    v8::Local<v8::Function> cons = Nan::New(constructor());

    String::Utf8Value group(info.GetIsolate(), info[0]);
    String::Utf8Value permission(info.GetIsolate(), info[1]);

    const int argc = 3;
    v8::Local<v8::Value> argv[argc] = {
      Nan::New(DENY_ACCESS),
      Nan::New(*group).ToLocalChecked(),
      Nan::New(*permission).ToLocalChecked(),
    };
    info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
  }

  Access *get() const { return m_Value; }

private:
  explicit AccessFactory(Access *value) : m_Value(value) {}

  ~AccessFactory() {
    delete m_Value;
  }

  static NAN_METHOD(New) {
    if (info.IsConstructCall()) {
      int access = info[0]->Int32Value(Nan::GetCurrentContext()).ToChecked();
      String::Utf8Value group(info.GetIsolate(), info[1]);
      String::Utf8Value permission(info.GetIsolate(), info[2]);

      AccessFactory *obj = new AccessFactory(new Access(static_cast<ACCESS_MODE>(access), *group, *permission));
      obj->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    }
    else {
      const int argc = 3;
      v8::Local<v8::Value> argv[argc] = { info[0], info[1], info[2] };
      v8::Local<v8::Function> cons = Nan::New(constructor());
      info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
    }
  }

  static inline Nan::Persistent<v8::Function> & constructor() {
    static Nan::Persistent<v8::Function> my_constructor;
    return my_constructor;
  }

  Access *m_Value;
};

std::string stringifyErr(DWORD code, const char *op) {
  std::string res;
  if (code == ERROR_ACCESS_DENIED) {
    res = std::string(op) + ": You don't have permission";
  } else if (code == ERROR_FILE_NOT_FOUND) {
    res = std::string(op) + ": File not found";
  } else if (code == ERROR_INVALID_NAME) {
    res = std::string(op) + ": Invalid name";
  } else {
    res = std::string(op) + " failed: " + std::to_string(code);
  }
  return res;
}

void apply(Access &access, const std::string &path) {
  std::wstring wpath = toWC(path.c_str(), CodePage::UTF8, path.size());

  PACL oldAcl;
  PSECURITY_DESCRIPTOR secDesc = nullptr;
  DWORD res = GetNamedSecurityInfoW(
    wpath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    nullptr, nullptr, &oldAcl, nullptr, &secDesc);
  if (res != ERROR_SUCCESS) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(res, "GetNamedSecurityInfoW", wpath.c_str()));
    return;
  }

  ON_BLOCK_EXIT([&] () {
    if (secDesc != nullptr) {
      LocalFree(secDesc);
    }
  });

  PACL newAcl = nullptr;

  res = SetEntriesInAclW(1, *access, oldAcl, &newAcl);
  if (res != ERROR_SUCCESS) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(res, "SetEntriesInAclW", wpath.c_str()));
    return;
  }

  ON_BLOCK_EXIT([&] () {
    if (newAcl != nullptr) {
      LocalFree(newAcl);
    }
  });

  // SetNamedSecurityInfo expects a non-const point to the path, but there is
  // no indication that it may actually get changed, much less that we need
  // to provide a larger buffer than necessary to hold the string
  res = SetNamedSecurityInfoW(&wpath[0], SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, nullptr, nullptr,
                              newAcl, nullptr);

  if (res != ERROR_SUCCESS) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(res, "SetNamedSecurityInfoW", wpath.c_str()));
    return;
  }
}

std::string getSid() {
  HANDLE token = GetCurrentProcess();
  if (!OpenProcessToken(token, TOKEN_READ, &token)) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(::GetLastError(), "OpenProcessToken"));
    return "";
  }

  TOKEN_USER *user = nullptr;
  DWORD required = 0;
  // pre-flight to get required buffer size
  GetTokenInformation(token, TokenUser, (void*)user, 0, &required);
  user = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required);
  ON_BLOCK_EXIT([&] () {
    if (user != nullptr) {
      HeapFree(GetProcessHeap(), 0, (void*)user);
    }
  });
  if (!GetTokenInformation(token, TokenUser, (void*)user, required, &required)) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(::GetLastError(), "GetTokenInformation"));
    return "";
  }

  LPWSTR stringSid = nullptr;
  if (!ConvertSidToStringSid(user->User.Sid, &stringSid)) {
    v8::Isolate::GetCurrent()->ThrowException(WinApiException(::GetLastError(), "ConvertSidToStringSid"));
    return "";
  }
  ON_BLOCK_EXIT([&] () {
    if (stringSid != nullptr) {
      LocalFree(stringSid);
    }
  });

  return toMB(stringSid, CodePage::UTF8, wcslen(stringSid));
}


NAN_METHOD(apply) {
  if (info.Length() != 2) {
    Nan::ThrowError("Expected parameters (access, path)");
    return;
  }

  Local<Object> access = Nan::To<Object>(info[0]).ToLocalChecked();
  String::Utf8Value path(info.GetIsolate(), info[1]);

  apply(*Nan::ObjectWrap::Unwrap<AccessFactory>(access)->get(), *path);
}

NAN_METHOD(getSid) {
  info.GetReturnValue().Set(Nan::New(getSid().c_str()).ToLocalChecked());
}

NAN_MODULE_INIT(Init) {
  AccessFactory::Init(target);
  Nan::Set(target, "grant"_n, GetFunction(Nan::New<v8::FunctionTemplate>(AccessFactory::Grant)).ToLocalChecked());
  Nan::Set(target, "deny"_n, GetFunction(Nan::New<v8::FunctionTemplate>(AccessFactory::Deny)).ToLocalChecked());

  Nan::Set(target, "apply"_n, GetFunction(New<FunctionTemplate>(apply)).ToLocalChecked());
  Nan::Set(target, "getSid"_n, GetFunction(New<FunctionTemplate>(getSid)).ToLocalChecked());
}

NODE_MODULE(winperm, Init)
