include $(TOPDIR)/rules.mk

PKG_NAME    := luci-app-telemt
PKG_VERSION := 3.3.26
PKG_RELEASE := 1

PKG_SOURCE_PROTO   := git
PKG_SOURCE_URL     := https://github.com/afadillo-a11y/luci-app-telemt.git
PKG_SOURCE_VERSION := $(PKG_VERSION)
PKG_SOURCE_DATE    := $(PKG_VERSION)
PKG_MIRROR_HASH    := skip

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER := afadillo-a11y
PKG_LICENSE    := GPL-2.0-only

PKG_BUILD_PARALLEL := 0

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-telemt
  SECTION   := luci
  CATEGORY  := LuCI
  SUBMENU   := 3. Applications
  TITLE     := LuCI support for Telemt MTProxy
  URL       := https://github.com/afadillo-a11y/luci-app-telemt
  PKGARCH   := all
  DEPENDS   := +luci-base +luci-compat +qrencode +ca-bundle +telemt
endef

define Package/luci-app-telemt/description
  LuCI web interface for the Telemt MTProxy daemon (v3.3.x+).

  Features:
    - Zero-Downtime Hot-Reload: add/update users without dropping sessions
    - Atomic TOML generation with mktemp + mv -f (no race conditions)
    - Dual routing badges: TG PATH (Direct-DC/ME/Fallback) and EGRESS
    - Telegram Bot sidecar daemon for remote management
    - CSV import/export of user database directly from browser
    - FakeTLS link and QR-code generation
    - Graceful shutdown: SIGTERM → stats save → SIGKILL
    - OpenWrt 25+ LuCI2 VDOM compatibility

  Requires: telemt binary v3.3.15+ (package: telemt)
  Architecture: noarch (pure Lua + shell scripts, any target)
endef

define Package/luci-app-telemt/install
	# Копируем всё дерево usr/ → /usr/ (Lua, bin, share, lib)
	$(CP) $(PKG_BUILD_DIR)/usr/. $(1)/usr/
endef

define Package/luci-app-telemt/postinst
#!/bin/sh

[ -x /etc/init.d/rpcd ] && \
    /etc/init.d/rpcd reload 2>/dev/null || true

exit 0
endef

define Package/luci-app-telemt/postrm
#!/bin/sh

rm -f /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null || true

[ -x /etc/init.d/rpcd ] && \
    /etc/init.d/rpcd restart 2>/dev/null || true

exit 0
endef

define Build/Compile
endef

$(eval $(call BuildPackage,luci-app-telemt))
