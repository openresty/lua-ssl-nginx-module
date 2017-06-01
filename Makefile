OPENRESTY_PREFIX=/usr/local/openresty-debug

PREFIX ?=          /usr/local
LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/lib/lua/$(LUA_VERSION)
INSTALL ?= install

.PHONY: install

install:
	$(INSTALL) -d $(DESTDIR)$(LUA_LIB_DIR)/ngx/ssl/session
	$(INSTALL) -d $(DESTDIR)$(LUA_LIB_DIR)/ngx/ssl/session/ticket
	$(INSTALL) lualib/ngx/ssl/session/*.lua $(DESTDIR)$(LUA_LIB_DIR)/ngx/ssl/session/
	$(INSTALL) lualib/ngx/ssl/session/ticket/*.lua $(DESTDIR)$(LUA_LIB_DIR)/ngx/ssl/session/ticket/
