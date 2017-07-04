-- Copyright (C) CloudFlare
--
-- implement SSL session ticket key auto-rotation timer
--


local _M = {}


local ticket_key = require "ngx.ssl.session.ticket"


local ngx_time = ngx.time
local str_format = string.format
local floor = math.floor
local str_char = string.char
local pseudo_random = math.random
local new_timer = ngx.timer.at
local update_enc_key = ticket_key.update_ticket_encryption_key
local update_last_dec_key = ticket_key.update_last_ticket_decryption_key
local assert = assert
local require = require
local io = io


local DEBUG = ngx.config.debug


local ticket_ttl
local time_slot
local memc_key_prefix


local fallback_random_key


local function dlog(ctx, ...)
    if DEBUG then
        ngx.log(ngx.DEBUG, "ticket key timer: ", ...)
    end
end


local function error_log(ctx, ...)
    ngx.log(ngx.ERR, "ticket key timer: ", ...)
end


local function fail(...)
    ngx.log(ngx.ERR, "ticket key timer: ", ...)
end


local function warn(...)
    if DEBUG then
        ngx.log(ngx.WARN, "ticket key timer: ", ...)
    end
end


local meta_shdict_set, meta_shdict_get
local fetch_key_from_memc

-- Store N+2 keys, including the current slot, the next slot and previous N
-- slots' key.
-- N = ticket_ttl / SEC_PER_HOUR
local nkeys


-- ticket keys are indexed by timestamps of time slots
local function ticket_key_index(now, offset)
    if not offset then offset = 0 end
    local t = floor(now / time_slot) * time_slot + offset * time_slot
    return memc_key_prefix .. t
end


-- get ticket key from shared dict. Ticket key should be protected
-- by some key encryption key. The ticket key would be decrypted
-- before being used. However here we leave it to users to finish
-- it.
local function shdict_get_and_decrypt(ctx, idx)
    local res, stale = meta_shdict_get(ctx, idx)

    if not res or stale or res == "" then
        if DEBUG then
            dlog(ctx, 'failed to get key from meta shdict: key index "',
                 idx, '"')
        end
        return nil
    end

    if DEBUG then
        dlog(ctx, "got enc key size ", #res)
    end

    local key = res
    -- TODO: Decrypt res into 48-byte key
    -- Ideally we should protect the ticket key with some encryption.
    -- key = decrypt(key, key_encryption_key)

    if #key ~= 48 then
      return fail("malformed key: #key ", #key)
    end

    return key
end


-- get ticket key from memcached. Ticket key should be protected
-- by some key encryption key. The ticket key would be decrypted
-- before being used. However here we leave it to users to finish
-- it.
local function memc_get_and_decrypt(ctx, idx, offset)
    if DEBUG then
        dlog(ctx, "ticket key index: ", idx, " time slot offset: ", offset)
    end

    local res, err = fetch_key_from_memc(ctx, idx)

    if not res or err then
        return fail('failed to get key from memc at time slot offset ', offset,
                        ', key index "', idx, '"', err)
    end

    if DEBUG then
        dlog(ctx, "got enc key size ", #res)
    end

    local key = res
    -- TODO: Decrypt res into 48-byte key
    -- Ideally we should protect the ticket key with some encryption.
    -- key = decrypt(key, key_encryption_key)

    if #key ~= 48 then
      return fail("malformed key: #key ", #key)
    end

    return key
end


local function update_ticket_encryption_key(ctx, key)
    if not key then
        if DEBUG then
            dlog(ctx, "encryption key is nil")
        end

        return
    end

    if DEBUG then
        dlog(ctx, "update ticket encryption key in OPENSSL ctx")
    end

    local ok, err
    ok, err = update_enc_key(key, nkeys)
    if not ok and err then
        return fail("failed to update encryption key: ", err)
    end
end


local function update_last_ticket_decryption_key(ctx, key)
    if not key then
         return
    end

    if DEBUG then
        dlog(ctx, "Update last ticket decryption key in OPENSSL ctx")
    end

    local ok, err
    ok, err = update_last_dec_key(key)
    if not ok and err then
        return fail("failed to update last decryption key: ", err)
    end
end


local function check(premature, bootstrap)
    if premature then
        return
    end

    local now = ngx_time()
    local next_time_slot = floor(now / time_slot + 1) * time_slot

    -- a random extra offset less than 100 ms to avoid concurrent update
    -- as well as off-by-one time slots.
    local epsilon = pseudo_random() * 0.1

    -- sleep until the next time slot
    local sleep_time = next_time_slot - now + epsilon
    local ok, err = new_timer(sleep_time, check)
    if not ok and err ~= "process exiting" then
        return fail("failed to create timer: ", err)
    end

    local ctx = {}
    local curr_key_index = ticket_key_index(now, 0)
    local next_key_index = ticket_key_index(now, 1)
    local curr_key, next_key

    if bootstrap then
        -- do a full sync with memc
        local previous_slots = floor(ticket_ttl / time_slot) + 1

        for i = -previous_slots, -1 do
            local idx = ticket_key_index(now, i)
            local key = memc_get_and_decrypt(ctx, idx, i)
            update_ticket_encryption_key(ctx, key)
        end
    end

    curr_key = memc_get_and_decrypt(ctx, curr_key_index, 0)

    if not curr_key then
        error_log(ctx, "unable to get current key from memc; ",
                     "use backup random key")
        curr_key = fallback_random_key
    end

    update_ticket_encryption_key(ctx, curr_key)

    next_key = memc_get_and_decrypt(ctx, next_key_index, 1)
    update_last_ticket_decryption_key(ctx, next_key)
end


function _M.start_update_timer()
    local ok, err = new_timer(0, check, true)
    if not ok then
        return fail("failed to create timer: ", err)
    end
end


function _M.init(opts)
    ticket_ttl = opts.ticket_ttl
    time_slot = opts.key_rotation_period
    memc_key_prefix = opts.memc_key_prefix

    local shdict_name = opts.cache_shdict_name
    local shm_cache_pos_ttl = opts.shm_cache_positive_ttl
    local shm_cache_neg_ttl = opts.shm_cache_negative_ttl
    local disable_shm_cache = opts.disable_shm_cache
    local locks_shdict_name = opts.locks_shdict_name

    local memc_host = opts.memc_host
    local memc_port = opts.memc_port
    local memc_timeout = opts.memc_timeout
    local memc_conn_pool_size = opts.memc_conn_pool_size
    local memc_fetch_retries = opts.memc_fetch_retries
    local memc_fetch_retry_delay = opts.memc_fetch_retry_delay

    local memc_conn_max_idle_time = opts.memc_conn_max_idle_time

    local frandom = assert(io.open("/dev/urandom", "rb"))
    fallback_random_key = frandom:read(48)
    frandom:close()

    nkeys = floor(ticket_ttl / time_slot) + 2
    do
        local meta_shdict = require "resty.shdict.simple"
        meta_shdict_set, meta_shdict_get = meta_shdict.gen_shdict_methods{
            dict_name = shdict_name,
            disable_shdict = disable_shm_cache,
            debug_logger = dlog,
            warn_logger = warn,
            error_logger = error_log,
            positive_ttl = shm_cache_pos_ttl,
            negative_ttl = shm_cache_neg_ttl,
        }
    end

    do
        local memc_shdict = require "resty.memcached.shdict"
        fetch_key_from_memc = memc_shdict.gen_memc_methods{
            tag = "ticket_memc",

            debug_logger = dlog,
            warn_logger = warn,
            error_logger = error_log,

            locks_shdict_name = locks_shdict_name,

            disable_shdict = disable_shm_cache,

            shdict_set = meta_shdict_set,
            shdict_get = meta_shdict_get,

            memc_host = memc_host,
            memc_port = memc_port,
            memc_timeout = memc_timeout,
            memc_conn_pool_size = memc_conn_pool_size,
            memc_fetch_retries = memc_fetch_retries,
            memc_fetch_retry_delay = memc_fetch_retry_delay,

            memc_conn_max_idle_time = memc_conn_max_idle_time,

            memc_store_retries = 0,
            memc_store_retry_delay = 0,
        }
    end

    local ctx = {}

    if DEBUG then
        dlog(ctx, "initialize session ticket key")
    end

    local now = ngx_time()
    local curr_key_index = ticket_key_index(now, 0)
    local curr_key

    if not disable_shm_cache then
        curr_key = shdict_get_and_decrypt(ctx, curr_key_index)
    end

    if not curr_key then
        update_ticket_encryption_key(ctx, fallback_random_key)

    else
        -- do a full sync with shdict
        local previous_slots = floor(ticket_ttl / time_slot) + 1

        for i = -previous_slots, 0 do
            local idx = ticket_key_index(now, i)
            local key = shdict_get_and_decrypt(ctx, idx)
            update_ticket_encryption_key(ctx, key)
         end
    end
end


return _M
