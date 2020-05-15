NAME
====

lua-ssl-nginx-module - NGINX C module that extends `ngx_http_lua_module` for enhanced SSL/TLS capabilities

Table of Contents
=================

* [NAME](#name)
* [Synopsis](#synopsis)
* [Description](#description)
* [Installation](#installation)
* [Author](#author)
* [Copyright and License](#copyright-and-license)

Synopsis
========

```nginx
http {
    lua_package_path "/path/to/lua-ssl-nginx-module/lualib/?.lua;;";

    lua_shared_dict my_cache 10m;
    lua_shared_dict locks 1m;

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
        }
    }

    init_worker_by_lua_block {
        require("ngx.ssl.session.ticket.key_rotation").start_update_timer()
    }

    server {
        listen 443 ssl;
        server_name "foo.com";

        # SSL session ticket key sharing
        # Put a dummy key to trigger external ticket key usage in nginx/OpenSSL
        # init_by_lua* will replace this dummy key with existing cached keys
        # or a random key if cached keys are not available.
        ssl_session_ticket_key  dummy.key;

        ...
    }

    ...
}
```

Description
===========

This NGINX module adds new Lua API and modules to OpenResty that enables more SSL/TLS
features like automatic TLS session ticket key manipulation and rotation (on the global
network level).

For global TLS session ticket key rotation, we require an external mechanism (could
be in a dedicated NGINX or OpenResty server itself, however) to feed
the TLS session ticket keys for each hour in Memcached servers or Memcached-compatible
servers (like Kyoto Tycoon). Each NGINX or OpenResty server node automatically queries the
Memcached server(s) with a key containing the timestamp every hour. It has the following
advantages:

1. We keep a list of keys inside the nginx server and only evict the oldest key every hour, which allows
gradual phase-out of old keys. The size of the list depends on the `ticket_ttl` and `key_rotation_period` settings.
1. The keys are updated automatically for all the virtual (SSL) servers defined in the `nginx.conf` file.
1. No NGINX server reload or restart is needed. New keys are pulled from Memcached or
Memcached-compatible servers automatically every hour.
1. All network I/O is 100% nonblocking, that is, it never blocks any OS threads nor the nginx event loop, even on shm cache misses.
1. All the core logic is in pure Lua, which is every easy to hack and adjust for special requirements.
1. Uses shm cache for the keys so that only one worker needs to query the Memcached or
Memcached-compatible servers. The shm cache can be disabled though.

NOTE: ticket key should be protected by some key encryption key. The ticket key should
be decrypted before being used. However we leave this to the user to handle.

Methods
=======

This section documents the methods for the `ngx.ssl.session.ticket.key_rotation` Lua module.

init
----
`syntax: module.init(opts)`

Initialize the settings of this module.

start_update_timer
------------------
`syntax: module.start_update_timer()`

Starts a recurring timer that periodically populates and rotates the ticket key list.
When invoked, it does three things:

1. Look up a ticket key for current time slot and insert
it to the beginning of the ticket key list.
2. Look up a ticket key for next time slot and replace the
the last element of the key list with it.
3. Start a new timer for next check.

Note we use rounded down timestamp based indexing in the shared
memcached to store/fetch ticket key.

For example, using a time slot of 1000 second, we would round
the timestamp down to the nearest 1000: 1001 -> 1000, 1987 -> 1000,
and 2001 -> 2000. In practice we usually use 1 hour as slot size.
You can check out the Lua function `ticket_key_index` for implementation details.

Timers across hosts are only loosely synchronized, there are cases that
host A is waken up by its timer and host B is not.
host A would start to use new key while session B is yet to load
it. The problem is solved by preloading the key for the next slot,
as described by item 2 above.

Installation
============

This module depends on [lua-nginx-module](https://github.com/openresty/lua-nginx-module).

If you are using the official nginx distribution, then build like this:

```bash
./configure --with-http_ssl_module \
            --add-module=/path/to/lua-nginx-module \
            --add-module=/path/to/lua-ssl-nginx-module
make
sudo make install
```

You can also compile this module as a dynamic module, by using the
`--add-dynamic-module=/path/to/lua-ssl-nginx-module` instead of `--add-module`
on the `./configure` command line above. Then load the module in `nginx.conf`
via the [`load_module`](https://nginx.org/en/docs/ngx_core_module.html#load_module)
directive.

Otherwise, if you are using the OpenResty distribution, build it as follows:

```bash
./configure --add-module=/path/to/lua-ssl-nginx-module
make
sudo make install
```

This module also ships with Lua modules under the `lualib/` directory. You can
configure the [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path)
directive like below:

```nginx
lua_package_path "/path/to/lua-ssl-nginx-module/lualib/?.lua;;";
```

Some of our Lua modules depend on the following Lua libraries:

* [lua-resty-shdict-simple](https://github.com/openresty/lua-resty-shdict-simple)
* [lua-resty-memcached-shdict](https://github.com/openresty/lua-resty-memcached-shdict)

[Back to TOC](#table-of-contents)

Author
======

* Zi Lin, Cloudflare Inc.
* Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>, Cloudflare Inc.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2016, by Cloudflare Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

