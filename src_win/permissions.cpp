#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <Sddl.h>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <nbind/api.h>

#include "scopeguard.h"
#include "string_cast.h"

class Access {
public:
  Access(Access &reference)
    : mAccess(reference.mAccess), mSid(reference.mSid)
  {
    reference.mOwner = false;
  }

  Access &operator=(const Access&) = delete;

  static Access grant(const std::string &group, const std::string &permission) {
    return Access(GRANT_ACCESS, group, permission);
  }

  static Access deny(const std::string &group, const std::string &permission) {
    return Access(DENY_ACCESS, group, permission);
  }

  ~Access() {
    if (mOwner) {
      LocalFree(mSid);
    }
  }

  PEXPLICIT_ACCESSW operator*() {
    return &mAccess;
  }
private:
  Access(ACCESS_MODE mode, const std::string &group, const std::string &permission) {
    mAccess.grfAccessMode = mode;
    mAccess.grfAccessPermissions = translatePermission(permission);
    mAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    mAccess.Trustee = makeTrustee(group);
  }

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
        std::ostringstream err;
        err << "Failed to create sid from group \"" << group << "\": " << ::GetLastError();
        throw std::runtime_error(err.str());
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
  PSID mSid;
};

void apply(Access &access, const std::string &path) {
  std::wstring wpath = toWC(path.c_str(), CodePage::UTF8, path.size());

  PACL oldAcl;
  PSECURITY_DESCRIPTOR secDesc;
  DWORD res = GetNamedSecurityInfoW(
    wpath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    nullptr, nullptr, &oldAcl, nullptr, &secDesc);
  if (res != ERROR_SUCCESS) {
    std::ostringstream err;
    err << "Failed to get ACL: " << res;
    NBIND_ERR(err.str().c_str());
    return;
  }

  ON_BLOCK_EXIT([&] () {
    LocalFree(secDesc);
  });

  PACL newAcl;

  res = SetEntriesInAclW(1, *access, oldAcl, &newAcl);
  if (res != ERROR_SUCCESS) {
    std::ostringstream err;
    err << "Failed to change ACL: " << res;
    NBIND_ERR(err.str().c_str());
    return;
  }

  ON_BLOCK_EXIT([&] () {
    LocalFree(newAcl);
  });

  // SetNamedSecurityInfo expects a non-const point to the path, but there is
  // no indication that it may actually get changed, much less that we need
  // to provide a larger buffer than necessary to hold the string
  res = SetNamedSecurityInfoW(&wpath[0], SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, nullptr, nullptr,
                              newAcl, nullptr);

  if (res != ERROR_SUCCESS) {
    std::ostringstream err;
    err << "Failed to apply ACL: " << res;
    NBIND_ERR(err.str().c_str());
    return;
  }
}

std::string getSid() {
  HANDLE token = GetCurrentProcess();
  if (!OpenProcessToken(token, TOKEN_READ, &token)) {
    std::ostringstream err;
    err << "Failed to open process token: " << GetLastError();
    NBIND_ERR(err.str().c_str());
    return "";
  }

  TOKEN_USER *user = nullptr;
  DWORD required = 0;
  // pre-flight to get required buffer size
  GetTokenInformation(token, TokenUser, (void*)user, 0, &required);
  user = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required);
  ON_BLOCK_EXIT([&] () {
    HeapFree(GetProcessHeap(), 0, (void*)user);
  });
  if (!GetTokenInformation(token, TokenUser, (void*)user, required, &required)) {
    std::ostringstream err;
    err << "Failed to get token information: " << GetLastError();
    NBIND_ERR(err.str().c_str());
    return "";
  }

  LPWSTR stringSid;
  if (!ConvertSidToStringSid(user->User.Sid, &stringSid)) {
    std::ostringstream err;
    err << "Failed to convert sid: " << GetLastError();
    NBIND_ERR(err.str().c_str());
    return "";
  }
  ON_BLOCK_EXIT([&] () {
    LocalFree(stringSid);
  });

  return toMB(stringSid, CodePage::UTF8, wcslen(stringSid));
}

#include <nbind/nbind.h>
 
NBIND_CLASS(Access) {
  method(grant);
  method(deny);
}

NBIND_GLOBAL() {
  function(apply);
  function(getSid);
}
