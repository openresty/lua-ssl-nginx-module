# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (blocks() * 3);

no_shuffle();
no_long_string();

our $pwd = `pwd`;
chomp $pwd;

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;
$ENV{TEST_NGINX_PWD} ||= $pwd;

run_tests();

__DATA__

=== TEST 1: 48 bit key
--- http_config
    lua_shared_dict my_cache 10m;
    lua_shared_dict locks 1m;
    lua_package_path '$TEST_NGINX_PWD/../lua-resty-lock/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-memcached/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-memcached-shdict/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-shdict-simple/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-core/lib/?.lua;$TEST_NGINX_PWD/lualib/?.lua;;';

    init_by_lua_block {
        require("ngx.ssl.session.ticket.key_rotation").init{
            locks_shdict_name = "locks",

            disable_shm_cache = false,  -- default false
            cache_shdict_name = "my_cache",
            shm_cache_positive_ttl = 24 * 3600 * 1000,   -- in ms
            shm_cache_negative_ttl = 0,   -- in ms

            ticket_ttl = 24 * 3600,   -- in sec
            key_rotation_period = 3600,   -- in sec

            memc_key_prefix = "ticket-key/",

            memc_host = "127.0.0.1",
            memc_port = 11211,
            memc_timeout = 500,  -- in ms
            memc_conn_pool_size = 1,
            memc_fetch_retries = 1,  -- optional, default 1
            memc_fetch_retry_delay = 100, -- in ms, optional, default to 100 (ms)

            memc_conn_max_idle_time = 1 * 1000,  -- in ms, for in-pool connections,
                                                  -- optional, default to nil
            key_length = 48   -- in bytes, optional, default 48, possible 80 if using with
                              -- nginx > 1.12.0, any other values it will
                              -- fallback to default length
        }
    }

    init_worker_by_lua_block {
        require("ngx.ssl.session.ticket.key_rotation").start_update_timer()
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_client_hello_by_lua_block { print("ssl client hello by lua is running!") }
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
        ssl_session_ticket_key  ../../cert/dummy-48.key;

        server_tokens off;
        location /foo {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("foo") ngx.exit(201) }
        }
    }

--- config
    location = /t {
        content_by_lua_block {
            ngx.say("Hello world")
        }
    }
--- request
GET /t
--- response_body
Hello world
--- timeout: 10
--- error_log
unable to get current key from memc; use backup random key



=== TEST 2: 80 bit key
--- http_config
    lua_shared_dict my_cache 10m;
    lua_shared_dict locks 1m;
    lua_package_path '$TEST_NGINX_PWD/../lua-resty-lock/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-memcached/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-memcached-shdict/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-shdict-simple/lib/?.lua;$TEST_NGINX_PWD/../lua-resty-core/lib/?.lua;$TEST_NGINX_PWD/lualib/?.lua;;';

    init_by_lua_block {
        require("ngx.ssl.session.ticket.key_rotation").init{
            locks_shdict_name = "locks",

            disable_shm_cache = false,  -- default false
            cache_shdict_name = "my_cache",
            shm_cache_positive_ttl = 24 * 3600 * 1000,   -- in ms
            shm_cache_negative_ttl = 0,   -- in ms

            ticket_ttl = 24 * 3600,   -- in sec
            key_rotation_period = 3600,   -- in sec

            memc_key_prefix = "ticket-key/",

            memc_host = "127.0.0.1",
            memc_port = 11211,
            memc_timeout = 500,  -- in ms
            memc_conn_pool_size = 1,
            memc_fetch_retries = 1,  -- optional, default 1
            memc_fetch_retry_delay = 100, -- in ms, optional, default to 100 (ms)

            memc_conn_max_idle_time = 1 * 1000,  -- in ms, for in-pool connections,
                                                  -- optional, default to nil
            key_length = 80   -- in bytes, optional, default 48, possible 80 if using with
                              -- nginx > 1.12.0, any other values it will
                              -- fallback to default length
        }
    }

    init_worker_by_lua_block {
        require("ngx.ssl.session.ticket.key_rotation").start_update_timer()
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_client_hello_by_lua_block { print("ssl client hello by lua is running!") }
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
        ssl_session_ticket_key  ../../cert/dummy-80.key;

        server_tokens off;
        location /foo {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("foo") ngx.exit(201) }
        }
    }

--- config
    location = /t {
        content_by_lua_block {
            ngx.say("Hello world")
        }
    }
--- request
GET /t
--- response_body
Hello world
--- timeout: 10
--- error_log
unable to get current key from memc; use backup random key
