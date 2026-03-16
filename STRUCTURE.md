<div align="center">
  <h1>🏗️ Project Architecture & Workflow</h1>
  <p><b>luci-app-telemt v3.3.16</b> | <i>How the Web UI, Init System, and Binary work together</i></p>
</div>

<hr>

<h2>📂 1. Directory & File Structure</h2>
<p>The repository mirrors the OpenWrt root filesystem. When the package is installed, files are placed exactly as structured below:</p>

<pre style="background-color: rgba(27,31,35,0.05); padding: 16px; border-radius: 6px; font-family: monospace; line-height: 1.4;">
📦 luci-app-telemt
 ┣ 📂 root/
 ┃ ┣ 📂 etc/
 ┃ ┃ ┣ 📂 config/
 ┃ ┃ ┃ ┗ 📜 <b>telemt</b>                 <span style="color: #6a737d;">// Default UCI configuration (The Single Source of Truth)</span>
 ┃ ┃ ┗ 📂 uci-defaults/
 ┃ ┃   ┗ 📜 <b>luci-telemt</b>            <span style="color: #6a737d;">// Post-install script (Registers UI menu, sets perms)</span>
 ┃ ┗ 📂 usr/
 ┃   ┣ 📂 lib/lua/luci/model/cbi/
 ┃   ┃ ┗ 📜 <b>telemt.lua</b>             <span style="color: #6a737d;">// 🧠 The Brains: Web UI Controller & AJAX Handler</span>
 ┃   ┗ 📂 share/telemt-luci/
 ┃     ┗ 📜 <b>init_script</b>            <span style="color: #6a737d;">// ⚙️ The Engine: Procd init.d script & TOML Generator</span>
 ┣ 📜 Makefile                     <span style="color: #6a737d;">// OpenWrt build recipe for .ipk</span>
 ┗ 📜 nfpm.yaml                    <span style="color: #6a737d;">// Multi-packager config (generates .ipk and .apk via GitHub Actions)</span>
</pre>

<hr>

<h2>📦 2. Installation Lifecycle (.ipk / .apk)</h2>
<p>When a user runs <code>opkg install luci-app-telemt.ipk</code> or uses the OpenWrt Software GUI, the following sequence occurs:</p>

<blockquote>
  <b>1. Extraction ➔ 2. Post-Install Hooks ➔ 3. Service Registration</b>
</blockquote>

<ul>
  <li>📥 <b>Extraction:</b> The package manager unpacks the <code>root/</code> directory into the router's root filesystem (<code>/</code>).</li>
  <li>🔌 <b>Menu Registration:</b> The script in <code>/etc/uci-defaults/</code> runs automatically. It tells LuCI to add the "Telemt Proxy" tab to the <i>Services</i> menu and clears the LuCI cache.</li>
  <li>🚀 <b>Init Setup:</b> The <code>init_script</code> is symlinked to <code>/etc/init.d/telemt</code> and enabled to run on router boot.</li>
</ul>

<hr>

<h2>🧩 3. Module Responsibilities</h2>

<details open>
  <summary><b><span style="font-size: 1.2em;">🖥️ The Web UI Controller (<code>telemt.lua</code>)</span></b></summary>
  <div style="padding-left: 20px; margin-top: 10px;">
    <ul>
      <li><b>Configuration Binding:</b> Connects HTML form elements directly to the <code>/etc/config/telemt</code> UCI file.</li>
      <li><b>AJAX Endpoints:</b> Intercepts <code>GET/POST</code> requests to fetch live Prometheus metrics, parse system logs, and check Procd firewall status without reloading the page.</li>
      <li><b>DOM Mutation & Graceful Degradation:</b> Contains a bulletproof client-side JS payload that detects the OpenWrt version. If it detects the strict LuCI2 VDOM (OpenWrt 25.x), it dynamically injects <code>[ user: name ]</code> into the Secret column to prevent rendering crashes.</li>
      <li><b>Link Generation:</b> Dynamically generates <code>tg://proxy</code> links locally in the browser based on the selected obfuscation mode (FakeTLS, DD, Classic) and domain.</li>
    </ul>
  </div>
</details>

<details open>
  <summary><b><span style="font-size: 1.2em;">⚙️ The Init Script & TOML Generator (<code>init_script</code>)</span></b></summary>
  <div style="padding-left: 20px; margin-top: 10px;">
    <ul>
      <li><b>Procd Management:</b> Handles daemon lifecycle (start/stop/reload), sets up respawn limits, and limits open files (nofile=65536).</li>
      <li><b>Smart Config Generation:</b> Reads the UCI config and generates a minimal, strict <code>/var/etc/telemt.toml</code>. It skips inactive features to keep the TOML clean.</li>
      <li><b>NAT & STUN Fallback:</b> Evaluates Network capabilities. If STUN is disabled in the UI, it smartly overrides the Prober by injecting the Announce IP directly into the listener block, allowing ME Proxy to work behind strict CGNAT.</li>
      <li><b>RAM Metrics Dump:</b> Intercepts shutdown signals, fetches the final Prometheus metrics via <code>uclient-fetch</code>, and saves accumulated user traffic to <code>/tmp/telemt_stats.txt</code> to prevent quota loss on restart.</li>
      <li><b>Dynamic Firewall:</b> Uses the Procd JSON API to temporarily open the proxy port in RAM. (Rule disappears cleanly on service stop).</li>
    </ul>
  </div>
</details>

<hr>

<h2>🔄 4. Operational Workflow (The Magic)</h2>
<p>How data flows from the user's browser down to the Rust binary and back:</p>

<table style="width:100%; text-align:left; border-collapse: collapse;">
  <tr style="background-color: rgba(0, 160, 0, 0.1);">
    <th style="padding: 10px; border: 1px solid #ddd;">Stage</th>
    <th style="padding: 10px; border: 1px solid #ddd;">Component</th>
    <th style="padding: 10px; border: 1px solid #ddd;">Action</th>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>1. Save</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">🌐 Web UI (LuCI)</td>
    <td style="padding: 10px; border: 1px solid #ddd;">User clicks "Save & Apply". LuCI writes all settings to <code>/etc/config/telemt</code>.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>2. Trigger</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">🛠️ System (Ubus)</td>
    <td style="padding: 10px; border: 1px solid #ddd;">OpenWrt detects UCI changes and calls <code>/etc/init.d/telemt reload</code>.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>3. Generate</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">⚙️ Init Script</td>
    <td style="padding: 10px; border: 1px solid #ddd;">Reads UCI, calculates CIDR whitelists, applies STUN logic, and writes <code>/var/etc/telemt.toml</code> into RAM.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>4. Execution</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">🚀 Procd</td>
    <td style="padding: 10px; border: 1px solid #ddd;">Spawns the <code>telemt</code> binary passing the TOML file as an argument. Injects firewall rules.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>5. Telemetry</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">📡 Telemt Binary</td>
    <td style="padding: 10px; border: 1px solid #ddd;">Listens on port <code>443</code> for users, caches TLS profiles in <code>/var/etc/telemt_tlsfront/</code>, and exposes metrics on <code>127.0.0.1:9091</code>.</td>
  </tr>
  <tr>
    <td style="padding: 10px; border: 1px solid #ddd;"><b>6. Feedback</b></td>
    <td style="padding: 10px; border: 1px solid #ddd;">🌐 Web UI (JS)</td>
    <td style="padding: 10px; border: 1px solid #ddd;">Every 2.5 seconds, JS fetches metrics via AJAX, parses the Prometheus text, and renders live speeds and dots directly in the User table.</td>
  </tr>
</table>

<br>
<p align="center">
  <i>Built for OpenWrt 21.02 — 25.x 🚀</i>
</p>
