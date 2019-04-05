-- Copyright (C) CloudFlare


local _M = {}


local ffi = require "ffi"
local C = ffi.C
local base = require "resty.core.base"
local ffi_cast = ffi.cast
local table_new = require "table.new"
local ffi_str = ffi.string


local get_string_buf = base.get_string_buf
local get_errmsg_ptr = base.get_errmsg_ptr
local void_ptr_type = ffi.typeof("void*")
local void_ptr_ptr_type = ffi.typeof("void**")
local ptr_size = ffi.sizeof(void_ptr_type)


ffi.cdef[[
int ngx_http_lua_ffi_get_ssl_ctx_count(void);
int ngx_http_lua_ffi_get_ssl_ctx_list(void **buf);
int ngx_http_lua_ffi_update_ticket_encryption_key(void *ctx,
     const unsigned char *key, unsigned int nkeys, char **err);
int ngx_http_lua_ffi_update_last_ticket_decryption_key(void *ctx,
     const unsigned char *key, char **err);
]]


local function get_ssl_ctx_list()
    local n = C.ngx_http_lua_ffi_get_ssl_ctx_count()
    local sz = ptr_size * n
    local raw_buf = get_string_buf(sz)
    local buf = ffi_cast(void_ptr_ptr_type, raw_buf)
    local rc = C.ngx_http_lua_ffi_get_ssl_ctx_list(buf)
    if rc == 0 then  -- NGX_OK
        local ret = table_new(n, 0)
        for i = 1, n do
            ret[i] = buf[i - 1]
        end
        return ret
    end

    return nil
end

_M.get_ssl_ctx_list = get_ssl_ctx_list

-- attempt to replace the ticket encryption key with key.
-- current encryption key will be rotated to become ticket decryption key.
-- returns ok, err
function _M.update_ticket_encryption_key(key, nkeys)
    local ctxs = get_ssl_ctx_list()
    local errmsg = get_errmsg_ptr()
    if not ctxs or #ctxs == 0 then
        return nil, 'no ssl ctx set'
    end

    -- OpenSSL session ticket key is 48 bytes.
    -- key structure:
    -- 16 bytes key name, 16 bytes AES key, 16 bytes HMAC key.
    if not key or #key ~= 48 then
        return nil, 'invalid ticket key'
    end

    for _, ctx in ipairs(ctxs) do
         local rc = C.ngx_http_lua_ffi_update_ticket_encryption_key(ctx,
                                                                    key,
                                                                    nkeys,
                                                                    errmsg)
         if rc ~= 0 then -- not NGX_OK
             return nil, ffi_str(errmsg[0])
         end
    end

    return "ok"
end

-- attempt to replace the last session ticket key with key.
-- returns ok, err
function _M.update_last_ticket_decryption_key(key)
    local ctxs = get_ssl_ctx_list()
    local errmsg = get_errmsg_ptr()
    if not ctxs then
        return nil, 'no ssl ctx set'
    end

    -- OpenSSL session ticket key is 48 bytes.
    if not key or #key ~= 48 then
        return nil, 'invalid ticket key'
    end

    for _, ctx in ipairs(ctxs) do
         local rc = C.ngx_http_lua_ffi_update_last_ticket_decryption_key(ctx,
                                                                         key,
                                                                         errmsg)
         if rc ~= 0 then -- not NGX_OK
             return nil, ffi_str(errmsg[0])
         end
    end

    return "ok"
end


return _M
