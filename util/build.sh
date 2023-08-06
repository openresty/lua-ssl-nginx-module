#!/usr/bin/env bash

# this file is mostly meant to be used by the author himself.

root=`pwd`
version=$1
force=$2
home=~

            #--with-cc=gcc46 \

ngx-build $force $version \
            --without-pcre2 \
            --with-ld-opt="-L$PCRE_LIB -Wl,-rpath,$PCRE_LIB:/usr/local/lib" \
            --with-cc-opt="-DDEBUG_MALLOC" \
            --with-http_stub_status_module \
            --with-http_ssl_module \
            --without-mail_pop3_module \
            --without-mail_imap_module \
            --without-mail_smtp_module \
            --without-http_upstream_ip_hash_module \
            --without-http_memcached_module \
            --without-http_referer_module \
            --without-http_autoindex_module \
            --without-http_auth_basic_module \
            --without-http_userid_module \
          --add-module=$root/../ndk-nginx-module \
          --add-module=$root/../lua-nginx-module \
          --add-module=$root $opts \
          --with-http_v2_module \
          --with-select_module \
          --with-poll_module \
          --without-http_ssi_module \
          --with-debug || exit 1
