-- ==============================================================================
-- Telemt LuCI Controller (Reverse Proxy & API Transport)
-- Version: 3.3.15
-- ==============================================================================

module("luci.controller.telemt", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/telemt") then
        return
    end

    -- Main menu entry under Services
    entry({"admin", "services", "telemt"}, cbi("telemt"), _("Telegram Proxy (MTProto)"), 60).dependent = true

    -- AJAX Transport Endpoints (Accessed only via JS client)
    -- Using .leaf = true to allow dynamic parameters if needed
    entry({"admin", "services", "telemt", "metrics"}, call("action_metrics"), nil).leaf = true
    entry({"admin", "services", "telemt", "scanners"}, call("action_scanners"), nil).leaf = true
    entry({"admin", "services", "telemt", "log"}, call("action_log"), nil).leaf = true
    entry({"admin", "services", "telemt", "fw_status"}, call("action_fw_status"), nil).leaf = true
    entry({"admin", "services", "telemt", "control"}, call("action_control"), nil).leaf = true
    entry({"admin", "services", "telemt", "csv_import"}, call("action_csv_import"), nil).leaf = true
    entry({"admin", "services", "telemt", "csv_export"}, call("action_csv_export"), nil).leaf = true
end

-- Helper: Determines the best fetch binary available in busybox
local function get_fetch_cmd()
    local sys = require "luci.sys"
    if os.execute("command -v wget >/dev/null 2>&1") == 0 then
        return "wget -q --timeout=3 -O -"
    else
        return "uclient-fetch -q --timeout=3 -O -"
    end
end

-- Proxy: Fetches Prometheus metrics and returns raw text to the browser for JS parsing
function action_metrics()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local uci = require("luci.model.uci").cursor()
    
    local m_port = tonumber(uci:get("telemt", "general", "metrics_port")) or 9092
    local fetch_cmd = get_fetch_cmd()
    
    http.prepare_content("text/plain")
    
    -- Only fetch if the daemon is running
    if sys.call("pidof telemt >/dev/null 2>&1") == 0 then
        local metrics = sys.exec(string.format("%s 'http://127.0.0.1:%d/metrics' 2>/dev/null", fetch_cmd, m_port)) or ""
        
        -- Append accumulated offline stats (preserved from 3.2.1 logic)
        local f = io.open("/tmp/telemt_stats.txt", "r")
        if f then 
            metrics = metrics .. "\n# ACCUMULATED\n"
            for line in f:lines() do 
                local u, tx, rx = line:match("^(%S+) (%S+) (%S+)$")
                if u then 
                    metrics = metrics .. string.format("telemt_accumulated_tx{user=\"%s\"} %s\ntelemt_accumulated_rx{user=\"%s\"} %s\n", u, tx, u, rx) 
                end 
            end
            f:close() 
        end
        http.write(metrics)
    else
        http.write("") -- Return empty if offline, JS will handle degraded state
    end
end

-- Proxy: Fetches active scanners list
function action_scanners()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local uci = require("luci.model.uci").cursor()
    
    local m_port = tonumber(uci:get("telemt", "general", "metrics_port")) or 9092
    local fetch_cmd = get_fetch_cmd()
    
    http.prepare_content("text/plain")
    local res = sys.exec(string.format("%s 'http://127.0.0.1:%d/beobachten' 2>/dev/null", fetch_cmd, m_port))
    
    if not res or res:gsub("%s+", "") == "" then 
        res = "No active scanners detected in quarantine." 
    end
    http.write(res)
end

-- Proxy: Reads system log efficiently using logread -e
function action_log()
    local sys = require "luci.sys"
    local http = require "luci.http"
    http.prepare_content("text/plain")
    
    local cmd = "logread -e 'telemt' | tail -n 100 2>/dev/null"
    if os.execute("command -v timeout >/dev/null 2>&1") == 0 then 
        cmd = "timeout 2 " .. cmd 
    end
    
    local log_data = sys.exec(cmd)
    if not log_data or log_data:gsub("%s+", "") == "" then 
        log_data = "No telemt log entries found." 
    end
    -- Strip ANSI color codes for clean HTML display
    log_data = log_data:gsub("\27%[[%d;]*m", "")
    http.write(log_data)
end

-- Proxy: Checks Firewall/Procd port status (Preserved from 3.2.1)
function action_fw_status()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local uci = require("luci.model.uci").cursor()
    
    local afw = uci:get("telemt", "general", "auto_fw") or "0"
    local port = tonumber(uci:get("telemt", "general", "port")) or 8443
    
    local cmd = string.format("/bin/sh -c \"iptables-save 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept' || nft list ruleset 2>/dev/null | grep -qiE 'Allow-Telemt-Magic|dport.*%d.*accept'\"", port, port)
    local is_physically_open = (sys.call(cmd) == 0)
    
    local procd_check = sys.exec("ubus call service list '{\"name\":\"telemt\"}' 2>/dev/null")
    local is_procd_open = (procd_check and procd_check:match("Allow%-Telemt%-Magic") ~= nil)
    local is_running = (sys.call("pidof telemt >/dev/null 2>&1") == 0)
    
    local status_msg, tip_msg = "<span style='color:red; font-weight:bold'>CLOSED</span>", "(Port not found in rules)"
    if is_physically_open then 
        status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"
        tip_msg = (afw == "0") and "(Auto-FW off, but port is open)" or ""
    elseif is_procd_open and is_running then 
        status_msg = "<span style='color:green; font-weight:bold'>OPEN (OK)</span>"
        tip_msg = "(Visible via ubus API)" 
    end
    
    if not is_running then 
        status_msg = "<span style='color:#d9534f; font-weight:bold'>SERVICE STOPPED</span> <span style='color:#888'>|</span> " .. status_msg 
    end
    
    http.prepare_content("text/plain")
    http.write(status_msg .. (tip_msg ~= "" and " <span style='color:#888; font-size:0.85em; margin-left:5px;'>" .. tip_msg .. "</span>" or ""))
end

-- Action: Process secure CSV Import (Migrated from 3.2.1)
function action_csv_import()
    local http = require "luci.http"
    local sys = require "luci.sys"
    local uci = require("luci.model.uci").cursor()
    
    local csv = http.formvalue("csv_data")
    local mode = http.formvalue("import_mode") or "replace"
    
    if not csv or csv == "" then
        http.prepare_content("application/json")
        http.write('{"status":"error","message":"Empty CSV data"}')
        return
    end
    
    local valid_users = {}
    local char_cr, char_lf, bom = string.char(13), string.char(10), string.char(239, 187, 191)
    
    -- Normalize line endings and remove BOM
    csv = csv:gsub("^" .. bom, ""):gsub(char_cr .. char_lf, char_lf):gsub(char_cr, char_lf)
    
    for line in csv:gmatch("[^" .. char_lf .. "]+") do
        if not line:match("^username,") and not line:match("^<") then
            local p = {}
            for f in (line..","):gmatch("([^,]*),") do 
                table.insert(p, (f:gsub("^%s*(.-)%s*$", "%1"))) 
            end
            
            local u, sec, c, uips, q, exp = p[1], p[2], p[3], p[4], p[5], p[6]
            
            -- Validation rules (Preserved from 3.2.1)
            if c and c ~= "" and c ~= "unlimited" and not c:match("^%d+$") then c = "" end
            if uips and uips ~= "" and uips ~= "unlimited" and not uips:match("^%d+$") then uips = "" end
            if q and q ~= "" and q ~= "unlimited" and not q:match("^%d+%.?%d*$") then q = "" end
            
            local sec_clean = nil
            if sec then
                sec = sec:match("secret=(%x+)") or sec
                local hex = sec:match("(%x+)")
                if hex then
                    local pfx = hex:sub(1,2):lower()
                    if pfx == "ee" or pfx == "dd" then hex = hex:sub(3) end
                    if #hex >= 32 then sec_clean = hex:sub(1, 32):lower() end
                end
            end
            
            -- Inject only if strictly valid
            if u and u ~= "" and u:match("^[A-Za-z0-9_]+$") and #u <= 15 and sec_clean then 
                table.insert(valid_users, {u=u, sec=sec_clean, c=c, uips=uips, q=q, exp=exp}) 
            end
        end
    end
    
    if #valid_users > 0 then
        if mode == "replace" then 
            local to_delete = {}
            uci:foreach("telemt", "user", function(s) table.insert(to_delete, s['.name']) end)
            for _, name in ipairs(to_delete) do uci:delete("telemt", name) end 
        end
        
        for _, v in ipairs(valid_users) do
            uci:set("telemt", v.u, "user")
            uci:set("telemt", v.u, "secret", v.sec)
            uci:set("telemt", v.u, "enabled", "1")
            
            if v.c and v.c ~= "" then uci:set("telemt", v.u, "max_tcp_conns", v.c) else uci:delete("telemt", v.u, "max_tcp_conns") end
            if v.uips and v.uips ~= "" then uci:set("telemt", v.u, "max_unique_ips", v.uips) else uci:delete("telemt", v.u, "max_unique_ips") end
            if v.q and v.q ~= "" then uci:set("telemt", v.u, "data_quota", v.q) else uci:delete("telemt", v.u, "data_quota") end
            if v.exp and v.exp:match("^%d%d%.%d%d%.%d%d%d%d %d%d:%d%d$") then uci:set("telemt", v.u, "expire_date", v.exp) else uci:delete("telemt", v.u, "expire_date") end
        end
        
        uci:save("telemt")
        uci:commit("telemt")
        sys.call("logger -t telemt \"WebUI: Successfully imported " .. #valid_users .. " users via CSV.\"")
        
        http.prepare_content("application/json")
        http.write('{"status":"ok", "imported":' .. #valid_users .. '}')
    else
        http.prepare_content("application/json")
        http.write('{"status":"error", "message":"No valid users found in CSV"}')
    end
end

-- Action: Service Control (Start/Stop/Restart/Reset Stats)
function action_control()
    local sys = require "luci.sys"
    local http = require "luci.http"
    local cmd = http.formvalue("cmd")
    
    if cmd == "start" then
        sys.call("logger -t telemt 'WebUI: Manual START requested'; /etc/init.d/telemt start")
    elseif cmd == "stop" then
        sys.call("logger -t telemt 'WebUI: Manual STOP requested'; /etc/init.d/telemt run_save_stats; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null")
    elseif cmd == "restart" then
        sys.call("logger -t telemt 'WebUI: Manual RESTART requested'; /etc/init.d/telemt run_save_stats; /etc/init.d/telemt stop; sleep 1; pidof telemt >/dev/null && killall -9 telemt 2>/dev/null; /etc/init.d/telemt start")
    elseif cmd == "reset_stats" then
        sys.call("logger -t telemt 'WebUI: Reset Traffic Stats'; rm -f /tmp/telemt_stats.txt")
    end
    
    http.prepare_content("application/json")
    http.write('{"status":"ok"}')
end
