NAME
====

lua-ssl-nginx-module - NGINX C module that extends `ngx_http_lua_module` for enhanced SSL/TLS capabilities

Description
===========

This NGINX module adds new Lua API and modules to OpenResty that enables more SSL/TLS
features like automatic TLS session ticket key manipulation and rotation (on the global
network level).

For global TLS session ticket key rotation, we require an external mechanism (could
be in a dedicated NGINX or OpenResty server itself, however) to feed
the TLS session ticket keys for each hour in Memcached servers or Memcached-compatible
servers (like Kyoto Tycoon). Each NGINX or OpenResty server node simply queries the
Memcached server(s) with a key containing the timestamp every hour. It has the following
advantages:

1. We keep a list of keys and only evict the oldest key every hour, which allows
gradual phase-out of old keys.
1. The keys are updated automatically for all the virtual (SSL) servers defined in the `nginx.conf` file.
1. No NGINX server reload or restart is needed. New keys are pulled from Memcached or
Memcached-compatible servers automatically every hour.
1. All network I/O is 100% nonblocking, that is, it never blocks any OS threads nor the nginx event loop.
1. All the core logic is in pure Lua, which is every easy to hack and adjust for special requirements.
1. Uses shm cache for the keys so that only one worker needs to query the Memcached or
Memcached-compatible servers.

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

