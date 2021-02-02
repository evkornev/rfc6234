#include "sha.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lua5.3/lauxlib.h>
#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>

// by now let's support only SHA256 hash func
SHAversion version = SHA256;

static int extract(lua_State *L){
  // by now let's support only SHA256 hash func
  int ret = 0;
  size_t salt_len = 0;
  size_t msg_len = 0;
  const char *salt = luaL_checklstring(L, 1, &salt_len);
  const char *msg = luaL_checklstring(L, 2, &msg_len);
  char secret[SHA256HashSize] = {0,};
  ret = hkdfExtract(version, salt, salt_len, msg, msg_len, secret);
  if (ret == 0){
      lua_pushlstring(L, secret, SHA256HashSize);
      return 1;
  }
  else{
      return 0;
  }
}

static int expand(lua_State *L){
  int ret = 0;
  size_t secret_len = 0;
  size_t info_len = 0;
  const char *secret = luaL_checklstring(L, 1, &secret_len);
  const char *info = luaL_checklstring(L, 2, &info_len);
  const int out_len = luaL_checkinteger(L, 3);
  unsigned char out[SHA256HashSize] = {0,};
  ret = hkdfExpand(version, secret, secret_len, info, info_len, out, out_len);
  if (ret == 0){
      lua_pushlstring(L, out, out_len);
      return 1;
  }
  else{
      return 0;
  }
}

static const luaL_Reg lhkdf[] = {
    {"extract", extract},
    {"expand", expand},
    {NULL, NULL},
};
int luaopen_lhkdf(lua_State *L)
{
    luaL_newlib(L, lhkdf);
    return 1;
}
