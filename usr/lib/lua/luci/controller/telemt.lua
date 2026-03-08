-- ==============================================================================
-- Telemt LuCI Controller
-- Provides backward compatibility for OpenWrt 21.02 and 22.03 menu generation
-- ==============================================================================

module("luci.controller.telemt", package.seeall)

function index()
    -- Register the menu entry under Services -> Telemt Proxy unconditionally
    local page = entry({"admin", "services", "telemt"}, cbi("telemt"), _("Telemt Proxy"), 90)
    page.dependent = true
    page.acl_depends = { "luci-app-telemt" }
end
