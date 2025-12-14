package webconsole

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"firecrackmanager/assets"
	"firecrackmanager/internal/api"
	"firecrackmanager/internal/database"
)

type WebConsole struct {
	db        *database.DB
	apiServer *api.Server
	mux       *http.ServeMux
}

func New(db *database.DB, apiServer *api.Server) *WebConsole {
	wc := &WebConsole{
		db:        db,
		apiServer: apiServer,
		mux:       http.NewServeMux(),
	}
	wc.registerRoutes()
	return wc
}

func (wc *WebConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle API routes
	if strings.HasPrefix(r.URL.Path, "/api/") {
		wc.apiServer.ServeHTTP(w, r)
		return
	}
	wc.mux.ServeHTTP(w, r)
}

func (wc *WebConsole) registerRoutes() {
	// Asset routes (embedded files)
	wc.mux.HandleFunc("/assets/", wc.handleAssets)

	wc.mux.HandleFunc("/", wc.handlePage)
	wc.mux.HandleFunc("/login", wc.handleLoginPage)
	wc.mux.HandleFunc("/logout", wc.handleLogout)
	wc.mux.HandleFunc("/dashboard", wc.requireAuth(wc.handleDashboard))
	wc.mux.HandleFunc("/vms", wc.requireAuth(wc.handleVMsPage))
	wc.mux.HandleFunc("/vms/", wc.requireAuth(wc.handleVMDetailPage))
	wc.mux.HandleFunc("/console/", wc.requireAuth(wc.handleConsolePage))
	wc.mux.HandleFunc("/vmgroups", wc.requireAdmin(wc.handleVMGroupsPage))
	wc.mux.HandleFunc("/networks", wc.requireAuth(wc.handleNetworksPage))
	wc.mux.HandleFunc("/images", wc.requireAuth(wc.handleImagesPage))
	wc.mux.HandleFunc("/docker", wc.requireAuth(wc.handleDockerPage))
	wc.mux.HandleFunc("/logs", wc.requireAuth(wc.handleLogsPage))
	wc.mux.HandleFunc("/settings", wc.requireAuth(wc.handleSettingsPage))
	wc.mux.HandleFunc("/account", wc.requireAuth(wc.handleAccountPage))
	wc.mux.HandleFunc("/migration", wc.requireAdmin(wc.handleMigrationPage))
	wc.mux.HandleFunc("/hostnetwork", wc.requireAdmin(wc.handleHostNetworkPage))
	wc.mux.HandleFunc("/users", wc.requireAdmin(wc.handleUsersPage))
	wc.mux.HandleFunc("/groups", wc.requireAdmin(wc.handleGroupsPage))
}

// handleAssets serves embedded static assets
func (wc *WebConsole) handleAssets(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/assets/")

	// Set cache headers for static assets (1 year)
	w.Header().Set("Cache-Control", "public, max-age=31536000")

	switch path {
	case "xterm.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(assets.XtermCSS)
	case "xterm.min.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write(assets.XtermJS)
	case "xterm-addon-fit.min.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write(assets.XtermAddonFitJS)
	case "material-icons.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(assets.MaterialIconsCSS))
	case "material-icons.ttf":
		w.Header().Set("Content-Type", "font/ttf")
		w.Write(assets.MaterialIconsTTF)
	case "apexcharts.min.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte(ApexChartsJS))
	case "Articafond3.png":
		w.Header().Set("Content-Type", "image/png")
		w.Write(LoginBackgroundPNG)
	default:
		http.NotFound(w, r)
	}
}

func (wc *WebConsole) getSession(r *http.Request) *database.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	sess, err := wc.db.GetSession(cookie.Value)
	if err != nil {
		return nil
	}
	return sess
}

func (wc *WebConsole) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := wc.getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		wc.db.ExtendSession(sess.ID, 24*time.Hour)
		next(w, r)
	}
}

func (wc *WebConsole) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := wc.getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if sess.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		wc.db.ExtendSession(sess.ID, 24*time.Hour)
		next(w, r)
	}
}

func (wc *WebConsole) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := wc.getSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (wc *WebConsole) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		wc.db.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (wc *WebConsole) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	if sess != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.renderLoginPage())
}

func (wc *WebConsole) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Dashboard", "dashboard", wc.renderDashboard(), sess))
}

func (wc *WebConsole) handleVMsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Virtual Machines", "vms", wc.renderVMsPage(), sess))
}

func (wc *WebConsole) handleVMDetailPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	vmID := strings.TrimPrefix(r.URL.Path, "/vms/")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("VM Details", "vms", wc.renderVMDetailPage(vmID), sess))
}

func (wc *WebConsole) handleConsolePage(w http.ResponseWriter, r *http.Request) {
	vmID := strings.TrimPrefix(r.URL.Path, "/console/")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.renderStandaloneConsolePage(vmID))
}

func (wc *WebConsole) handleNetworksPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Networks", "networks", wc.renderNetworksPage(), sess))
}

func (wc *WebConsole) handleImagesPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Images", "images", wc.renderImagesPage(), sess))
}

func (wc *WebConsole) handleDockerPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Docker Images", "docker", wc.renderDockerPage(), sess))
}

func (wc *WebConsole) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Logs", "logs", wc.renderLogsPage(), sess))
}

func (wc *WebConsole) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Settings", "settings", wc.renderSettingsPage(), sess))
}

func (wc *WebConsole) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("My Account", "account", wc.renderAccountPage(), sess))
}

func (wc *WebConsole) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Users", "users", wc.renderUsersPage(), sess))
}

func (wc *WebConsole) handleGroupsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Groups", "groups", wc.renderGroupsPage(), sess))
}

func (wc *WebConsole) renderLoginPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=Edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
    <title>Login - FireCrackManager</title>
    <link href="/assets/material-icons.css" rel="stylesheet">
    <style>` + LoginPageCSS + `</style>
</head>
<body class="wrapper">
    <form id="loginForm">
        <div class="main-container">
            <div class="title-row">
                <div class="title-name">
                    <span class="material-icons">local_fire_department</span>
                    <span>Connection</span>
                </div>
                <div class="subtitle">FireCrackManager</div>
                <div id="login-fields">
                    <div class="description">
                        Welcome to the FireCrackManager Web Administration Interface.<br>
                        Please use your Manager account or any account defined by your Administrator.
                    </div>
                    <div class="error-hint" id="error"></div>
                    <input type="text" id="username" name="username" class="form-input"
                           placeholder="User name" autocapitalize="off" autocomplete="off" tabindex="1">
                    <input type="password" id="password" name="password" class="form-input"
                           placeholder="Password" autocapitalize="off" autocomplete="off" tabindex="2">
                    <button type="submit" class="login-button">Login&nbsp;&raquo;&raquo;</button>
                </div>
            </div>
            <p class="version-info">FireCrackManager v1.0.0 &copy; 2025</p>
        </div>
    </form>
    <script>
        function initial() {
            document.getElementById('username').focus();
            document.getElementById('username').onkeyup = function(e) {
                e = e || event;
                if (e.keyCode == 13) {
                    document.getElementById('password').focus();
                    return false;
                }
            };
            document.getElementById('username').onkeypress = function(e) {
                e = e || event;
                if (e.keyCode == 13) { return false; }
            };
            document.getElementById('password').onkeyup = function(e) {
                e = e || event;
                if (e.keyCode == 13) {
                    login();
                    return false;
                }
            };
            document.getElementById('password').onkeypress = function(e) {
                e = e || event;
                if (e.keyCode == 13) { return false; }
            };
        }

        async function login() {
            const error = document.getElementById('error');
            error.style.display = 'none';

            try {
                const resp = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    })
                });
                const data = await resp.json();
                if (resp.ok) {
                    window.location.href = '/dashboard';
                } else {
                    error.textContent = data.error || 'Login failed';
                    error.style.display = 'block';
                }
            } catch (err) {
                error.textContent = 'Connection error';
                error.style.display = 'block';
            }
        }

        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            login();
        });

        initial();
    </script>
</body>
</html>`
}

func (wc *WebConsole) baseTemplate(title, page, content string, session *database.Session) string {
	isAdmin := session != nil && session.Role == "admin"
	username := ""
	if session != nil {
		username = session.Username
	}

	// Host Network menu item (only shown if enabled in config)
	hostNetworkMenu := ""
	if wc.apiServer.IsHostNetworkManagementEnabled() {
		hostNetworkMenu = `<a href="/hostnetwork" class="nav-item" data-page="hostnetwork">
                <span class="material-icons">lan</span>
                <span>Host Network</span>
            </a>`
	}

	adminMenu := ""
	if isAdmin {
		adminMenu = `<a href="/vmgroups" class="nav-item" data-page="vmgroups">
            <span class="material-icons">folder_special</span>
            <span>VM Groups</span>
        </a>
        <a href="/users" class="nav-item" data-page="users">
            <span class="material-icons">people</span>
            <span>Users</span>
        </a>
        <a href="/groups" class="nav-item" data-page="groups">
            <span class="material-icons">group_work</span>
            <span>Groups</span>
        </a>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - FireCrackManager</title>
    <link href="/assets/material-icons.css" rel="stylesheet">
    <style>`+MainLayoutCSS+`</style>
    <script>
        // Common utility functions - must be in head so they're available to page scripts
        // Modal functions
        function openModal(id) {
            document.getElementById(id).classList.add('active');
        }
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        // API helper
        async function apiCall(url, method = 'GET', body = null) {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' }
            };
            if (body) options.body = JSON.stringify(body);
            const resp = await fetch(url, options);
            return { ok: resp.ok, data: await resp.json() };
        }

        // Format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Format date
        function formatDate(dateStr) {
            return new Date(dateStr).toLocaleString();
        }

        // Toggle dropdown menu
        function toggleDropdown(btn) {
            const dropdown = btn.nextElementSibling;
            const wasOpen = dropdown.classList.contains('show');
            // Close all dropdowns first
            document.querySelectorAll('.dropdown-menu.show').forEach(m => m.classList.remove('show'));
            // Toggle this one
            if (!wasOpen) {
                dropdown.classList.add('show');
            }
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.dropdown')) {
                document.querySelectorAll('.dropdown-menu.show').forEach(m => m.classList.remove('show'));
            }
        });
    </script>
</head>
<body>
    <aside class="sidebar">
        <div class="sidebar-header">
            <span class="material-icons">local_fire_department</span>
            <h1>FireCrackManager</h1>
        </div>
        <nav>
            <a href="/dashboard" class="nav-item" data-page="dashboard">
                <span class="material-icons">dashboard</span>
                <span>Dashboard</span>
            </a>
            <a href="/vms" class="nav-item" data-page="vms">
                <span class="material-icons">memory</span>
                <span>Virtual Machines</span>
            </a>
            <a href="/networks" class="nav-item" data-page="networks">
                <span class="material-icons">hub</span>
                <span>Networks</span>
            </a>
            <a href="/images" class="nav-item" data-page="images">
                <span class="material-icons">storage</span>
                <span>Images</span>
            </a>
            <a href="/docker" class="nav-item" data-page="docker">
                <span class="material-icons">cloud_download</span>
                <span>Docker Images</span>
            </a>
            <a href="/logs" class="nav-item" data-page="logs">
                <span class="material-icons">article</span>
                <span>Logs</span>
            </a>
            <a href="/settings" class="nav-item" data-page="settings">
                <span class="material-icons">settings</span>
                <span>Settings</span>
            </a>
            <a href="/migration" class="nav-item" data-page="migration">
                <span class="material-icons">swap_horiz</span>
                <span>Migration</span>
            </a>
            %s
            %s
        </nav>
    </aside>
    <main class="main-content">
        <header class="topbar">
            <h2>%s</h2>
            <div class="user-menu">
                <a href="/account" class="user-link" title="My Account">
                    <span class="material-icons">account_circle</span>
                    <span>%s</span>
                </a>
                <a href="/logout">Logout</a>
            </div>
        </header>
        <div class="content">
            %s
        </div>
    </main>
    <script>
        // Highlight active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            if (item.dataset.page === '%s') {
                item.classList.add('active');
            }
        });
    </script>
</body>
</html>`, title, hostNetworkMenu, adminMenu, title, username, content, page)
}

func (wc *WebConsole) renderDashboard() string {
	return `
<div class="dashboard-grid">
    <!-- Virtual Machines Widget -->
    <div class="ibox">
        <div class="ibox-title">
            <h5>Virtual Machines</h5>
            <span class="label label-primary" id="vmStatusLabel">-</span>
        </div>
        <div class="ibox-content">
            <h1 id="vmCount">-</h1>
            <div class="stat-percent text-success" id="vmRunning">- running <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
            <small>Total VMs</small>
        </div>
        <div class="ibox-footer">
            <canvas id="vmChart"></canvas>
        </div>
    </div>

    <!-- CPU Widget -->
    <div class="ibox">
        <div class="ibox-title">
            <h5>System CPU</h5>
            <span class="label label-primary" id="cpuStatusLabel">OK</span>
        </div>
        <div class="ibox-content">
            <h1 id="cpuPercent">-%</h1>
            <div class="stat-percent text-success" id="cpuCores">- CPUs <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
            <small>Used CPU</small>
        </div>
        <div class="ibox-footer">
            <canvas id="cpuChart"></canvas>
        </div>
    </div>

    <!-- Memory Widget -->
    <div class="ibox">
        <div class="ibox-title">
            <h5>System Memory</h5>
            <span class="label label-primary" id="memStatusLabel">OK</span>
        </div>
        <div class="ibox-content">
            <h1 id="memUsed">-</h1>
            <div class="stat-percent text-success" id="memPercent">-% <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
            <small id="memTotal">Total: -</small>
        </div>
        <div class="ibox-footer">
            <canvas id="memChart"></canvas>
        </div>
    </div>

    <!-- Disk Usage Widget -->
    <div class="ibox">
        <div class="ibox-title">
            <h5>Disk Usage</h5>
            <span class="label label-primary" id="diskStatusLabel">OK</span>
        </div>
        <div class="ibox-content">
            <h1 id="diskUsed">-</h1>
            <div class="stat-percent text-success" id="diskPercent">-% <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
            <small id="diskTotal">Total: -</small>
        </div>
        <div class="ibox-footer" style="padding: 15px;">
            <div class="disk-progress-container">
                <div class="disk-progress-bar" id="diskProgressBar"></div>
            </div>
            <div class="disk-progress-labels">
                <span id="diskFreeLabel">- free</span>
                <span id="diskUsedLabel">- used</span>
            </div>
        </div>
    </div>
</div>

<style>
.disk-progress-container {
    width: 100%;
    height: 12px;
    background: #e8e8e8;
    border-radius: 6px;
    overflow: hidden;
}
.disk-progress-bar {
    height: 100%;
    background: #18a689;
    border-radius: 6px;
    transition: width 0.3s ease, background-color 0.3s ease;
}
.disk-progress-labels {
    display: flex;
    justify-content: space-between;
    margin-top: 6px;
    font-size: 11px;
    color: var(--text-secondary);
}
</style>

<div class="card">
    <div class="card-header">
        <h3>Recent Activity</h3>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>VM</th>
                    <th>Level</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody id="recentLogs">
                <tr><td colspan="4">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
// Simple sparkline chart using canvas
function drawSparkline(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.parentElement.offsetWidth - 30;
    const height = 40;
    canvas.width = width;
    canvas.height = height;

    if (!data || data.length === 0) {
        data = [0];
    }

    const max = Math.max(...data, 1);
    const min = Math.min(...data, 0);
    const range = max - min || 1;
    const step = width / (data.length - 1 || 1);

    // Fill
    ctx.beginPath();
    ctx.moveTo(0, height);
    data.forEach((val, i) => {
        const x = i * step;
        const y = height - ((val - min) / range) * (height - 5);
        ctx.lineTo(x, y);
    });
    ctx.lineTo(width, height);
    ctx.closePath();
    ctx.fillStyle = '#eeeeee';
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((val, i) => {
        const x = i * step;
        const y = height - ((val - min) / range) * (height - 5);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color || '#18a689';
    ctx.lineWidth = 2;
    ctx.stroke();
}

// History data for sparklines
let vmHistory = [];
let cpuHistory = [];
let memHistory = [];

// Update disk usage progress bar
function updateDiskProgressBar(usedPercent) {
    const bar = document.getElementById('diskProgressBar');
    if (!bar) return;

    bar.style.width = usedPercent + '%';

    // Change color based on usage: green < 75%, yellow 75-90%, red > 90%
    if (usedPercent >= 90) {
        bar.style.background = '#ed5565'; // red
    } else if (usedPercent >= 75) {
        bar.style.background = '#f8ac59'; // yellow/warning
    } else {
        bar.style.background = '#18a689'; // green
    }
}

async function loadDashboard() {
    const { ok, data } = await apiCall('/api/stats');
    if (ok) {
        const vmTotal = data.vms?.total || 0;
        const vmRunning = data.vms?.running || 0;
        document.getElementById('vmCount').textContent = vmTotal;
        document.getElementById('vmRunning').innerHTML = vmRunning + ' running <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
        document.getElementById('vmStatusLabel').textContent = vmRunning > 0 ? 'Active' : 'Idle';
        document.getElementById('vmStatusLabel').className = 'label ' + (vmRunning > 0 ? 'label-success' : 'label-primary');

        // Update history
        vmHistory.push(vmRunning);
        if (vmHistory.length > 20) vmHistory.shift();

        drawSparkline('vmChart', vmHistory, '#18a689');
    }

    // Get system stats
    const sysResp = await apiCall('/api/system/status');
    if (sysResp.ok && sysResp.data) {
        const sys = sysResp.data;

        // CPU
        const cpuPercent = sys.cpu_percent || 0;
        document.getElementById('cpuPercent').textContent = cpuPercent.toFixed(0) + '%';
        document.getElementById('cpuCores').innerHTML = (sys.cpu_cores || '-') + ' CPUs <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
        const cpuLabel = document.getElementById('cpuStatusLabel');
        if (cpuPercent > 80) {
            cpuLabel.textContent = 'High';
            cpuLabel.className = 'label label-danger';
        } else if (cpuPercent > 50) {
            cpuLabel.textContent = 'Medium';
            cpuLabel.className = 'label label-warning';
        } else {
            cpuLabel.textContent = 'OK';
            cpuLabel.className = 'label label-success';
        }

        cpuHistory.push(cpuPercent);
        if (cpuHistory.length > 20) cpuHistory.shift();
        drawSparkline('cpuChart', cpuHistory, '#18a689');

        // Memory
        const memUsedMB = sys.mem_used_mb || 0;
        const memTotalMB = sys.mem_total_mb || 1;
        const memPct = (memUsedMB / memTotalMB * 100);
        document.getElementById('memUsed').textContent = formatMemory(memUsedMB);
        document.getElementById('memPercent').innerHTML = memPct.toFixed(1) + '% <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
        document.getElementById('memTotal').textContent = 'Total: ' + formatMemory(memTotalMB);
        const memLabel = document.getElementById('memStatusLabel');
        if (memPct > 80) {
            memLabel.textContent = 'High';
            memLabel.className = 'label label-danger';
        } else if (memPct > 50) {
            memLabel.textContent = 'Medium';
            memLabel.className = 'label label-warning';
        } else {
            memLabel.textContent = 'OK';
            memLabel.className = 'label label-success';
        }

        memHistory.push(memPct);
        if (memHistory.length > 20) memHistory.shift();
        drawSparkline('memChart', memHistory, '#18a689');

        // Disk Usage
        const diskUsedGB = sys.disk_used_gb || 0;
        const diskTotalGB = sys.disk_total_gb || 1;
        const diskFreeGB = diskTotalGB - diskUsedGB;
        const diskPct = sys.disk_percent || 0;
        document.getElementById('diskUsed').textContent = diskUsedGB.toFixed(1) + ' GB';
        document.getElementById('diskPercent').innerHTML = diskPct.toFixed(1) + '% <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
        document.getElementById('diskTotal').textContent = 'Total: ' + diskTotalGB.toFixed(1) + ' GB';
        document.getElementById('diskFreeLabel').textContent = diskFreeGB.toFixed(1) + ' GB free';
        document.getElementById('diskUsedLabel').textContent = diskUsedGB.toFixed(1) + ' GB used';
        const diskLabel = document.getElementById('diskStatusLabel');
        if (diskPct >= 90) {
            diskLabel.textContent = 'Critical';
            diskLabel.className = 'label label-danger';
        } else if (diskPct >= 75) {
            diskLabel.textContent = 'Warning';
            diskLabel.className = 'label label-warning';
        } else {
            diskLabel.textContent = 'OK';
            diskLabel.className = 'label label-success';
        }

        updateDiskProgressBar(diskPct);
    }

    const logsResp = await apiCall('/api/logs?limit=10');
    if (logsResp.ok && logsResp.data.logs) {
        const tbody = document.getElementById('recentLogs');
        if (logsResp.data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No recent activity</td></tr>';
        } else {
            tbody.innerHTML = logsResp.data.logs.map(log => ` + "`" + `
                <tr>
                    <td>${formatDate(log.created_at)}</td>
                    <td>${log.vm_id.substring(0, 8)}...</td>
                    <td><span class="badge badge-${log.level === 'error' ? 'danger' : log.level === 'warning' ? 'warning' : 'info'}">${log.level}</span></td>
                    <td>${log.message}</td>
                </tr>
            ` + "`" + `).join('');
        }
    }
}

function formatMemory(mb) {
    if (mb >= 1024) {
        return (mb / 1024).toFixed(2) + ' GB';
    }
    return mb.toFixed(0) + ' MB';
}

loadDashboard();
setInterval(loadDashboard, 5000);
</script>
`
}

func (wc *WebConsole) renderVMsPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Virtual Machines</h3>
        <div style="display: flex; gap: 8px; align-items: center;">
            <div class="btn-group view-toggle" style="margin-right: 8px;">
                <button class="btn btn-sm active" id="listViewBtn" onclick="switchToListView()" title="List View">
                    <span class="material-icons">view_list</span>
                </button>
                <button class="btn btn-sm" id="groupViewBtn" onclick="switchToGroupView()" title="Group View">
                    <span class="material-icons">account_tree</span>
                </button>
            </div>
            <button class="btn btn-primary" onclick="openModal('createVMModal')">
                <span class="material-icons">add</span>
                Create VM
            </button>
            <button class="btn btn-secondary" onclick="openImportModal()">
                <span class="material-icons">upload</span>
                Import VM
            </button>
        </div>
    </div>
    <!-- Search Bar -->
    <div class="card-section" style="padding: 1rem; border-bottom: 1px solid var(--border); background: var(--bg-secondary);">
        <div class="vm-search-container">
            <div class="search-main">
                <span class="material-icons search-icon">search</span>
                <input type="text" id="vmSearchQuery" placeholder="Search VMs by name, IP, or MAC..." oninput="debounceSearch()">
                <button class="btn btn-sm" onclick="toggleAdvancedSearch()" title="Advanced search">
                    <span class="material-icons">tune</span>
                </button>
                <button class="btn btn-sm" onclick="clearSearch()" title="Clear search">
                    <span class="material-icons">clear</span>
                </button>
            </div>
            <div id="advancedSearchPanel" class="advanced-search" style="display: none;">
                <div class="search-filters">
                    <div class="filter-group">
                        <label>Status</label>
                        <select id="vmFilterStatus" onchange="applySearch()">
                            <option value="">All</option>
                            <option value="running">Running</option>
                            <option value="stopped">Stopped</option>
                            <option value="error">Error</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Network</label>
                        <select id="vmFilterNetwork" onchange="applySearch()">
                            <option value="">All Networks</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>VM Group</label>
                        <select id="vmFilterVMGroup" onchange="applySearch()">
                            <option value="">All Groups</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>OS</label>
                        <input type="text" id="vmFilterOS" placeholder="e.g., Ubuntu, Alpine" oninput="debounceSearch()">
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="card-body">
        <div id="searchResultInfo" style="display: none; padding: 0.5rem 0; color: var(--text-secondary); font-size: 0.9rem;"></div>
        <!-- List View -->
        <div id="vmListView">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>vCPU</th>
                        <th>Memory</th>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>&nbsp;</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="vmList">
                    <tr><td colspan="7">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <!-- Group View -->
        <div id="vmGroupView" style="display: none;">
            <div id="vmGroupTree" class="vm-group-tree">
                <div class="loading">Loading...</div>
            </div>
        </div>
    </div>
</div>

<style>
.vm-search-container { display: flex; flex-direction: column; gap: 0.75rem; }
.search-main { display: flex; align-items: center; gap: 0.5rem; }
.search-main input { flex: 1; padding: 0.5rem 0.5rem 0.5rem 2rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.9rem; }
.search-icon { position: absolute; margin-left: 0.5rem; color: var(--text-secondary); pointer-events: none; }
.search-main { position: relative; }
.advanced-search { padding-top: 0.75rem; border-top: 1px solid var(--border); margin-top: 0.5rem; }
.search-filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
.filter-group { display: flex; flex-direction: column; gap: 0.25rem; }
.filter-group label { font-size: 0.8rem; color: var(--text-secondary); }
.filter-group select, .filter-group input { padding: 0.4rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.85rem; }

/* View toggle buttons */
.view-toggle { display: flex; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
.view-toggle .btn { border: none; border-radius: 0; padding: 6px 10px; background: var(--bg-secondary); color: var(--text-secondary); }
.view-toggle .btn:not(:last-child) { border-right: 1px solid var(--border); }
.view-toggle .btn.active { background: var(--primary); color: white; }
.view-toggle .btn:hover:not(.active) { background: var(--bg-tertiary); }

/* VM Group Tree View */
.vm-group-tree { padding: 0.5rem 0; }
.vm-group-item { margin-bottom: 0.5rem; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.vm-group-header { display: flex; align-items: center; padding: 12px 16px; background: var(--bg-secondary); cursor: pointer; user-select: none; }
.vm-group-header:hover { background: var(--bg-tertiary); }
.vm-group-header .material-icons.toggle-icon { margin-right: 8px; transition: transform 0.2s; color: var(--text-secondary); }
.vm-group-header.collapsed .toggle-icon { transform: rotate(-90deg); }
.vm-group-header .group-icon { margin-right: 8px; color: var(--primary); }
.vm-group-header .group-name { font-weight: 500; flex: 1; }
.vm-group-header .vm-count { font-size: 0.85rem; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 12px; }
.vm-group-content { border-top: 1px solid var(--border); }
.vm-group-content.collapsed { display: none; }
.vm-group-vm { display: flex; align-items: center; padding: 10px 16px 10px 44px; border-bottom: 1px solid var(--border); }
.vm-group-vm:last-child { border-bottom: none; }
.vm-group-vm:hover { background: var(--bg-secondary); }
.vm-group-vm .vm-icon { margin-right: 10px; font-size: 20px; }
.vm-group-vm .vm-icon.running { color: var(--success); }
.vm-group-vm .vm-icon.stopped { color: var(--warning); }
.vm-group-vm .vm-icon.error { color: var(--danger); }
.vm-group-vm .vm-info { flex: 1; }
.vm-group-vm .vm-name { font-weight: 500; }
.vm-group-vm .vm-name a { color: var(--text); text-decoration: none; }
.vm-group-vm .vm-name a:hover { color: var(--primary); }
.vm-group-vm .vm-details { font-size: 0.85rem; color: var(--text-secondary); margin-top: 2px; }
.vm-group-vm .vm-status { margin-left: 12px; }
.vm-group-vm .vm-actions { margin-left: 12px; }
.vm-group-empty { padding: 20px 44px; color: var(--text-secondary); font-style: italic; }
</style>

<div id="createVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Virtual Machine</h3>
            <span class="material-icons modal-close" onclick="closeModal('createVMModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createVMForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" required>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" value="1" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" value="512" min="128" step="128">
                </div>
                <div class="form-group">
                    <label>Kernel</label>
                    <select name="kernel_id" required id="kernelSelect">
                        <option value="">Select kernel...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Root Filesystem</label>
                    <select name="rootfs_id" required id="rootfsSelect">
                        <option value="">Select rootfs...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Network</label>
                    <select name="network_id" id="networkSelect">
                        <option value="">No network</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Kernel Arguments (optional)</label>
                    <input type="text" name="kernel_args" placeholder="console=ttyS0,115200n8 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" placeholder="8.8.8.8,8.8.4.4">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
                </div>
                <div class="form-group">
                    <label>Snapshot Type (optional)</label>
                    <select name="snapshot_type" id="snapshotTypeSelect">
                        <option value="">Disabled</option>
                        <option value="Full">Full Snapshot</option>
                        <option value="Diff">Differential Snapshot</option>
                    </select>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Enable Firecracker snapshot feature for VM state preservation.</small>
                </div>
                <div class="form-group">
                    <label>Data Disk (optional)</label>
                    <select name="data_disk_id" id="dataDiskSelect">
                        <option value="">No data disk</option>
                    </select>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Attach an additional data disk to the VM.</small>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createVMModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createVM()">Create</button>
        </div>
    </div>
</div>

<div id="editVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Edit Virtual Machine</h3>
            <span class="material-icons modal-close" onclick="closeModal('editVMModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="editVMForm">
                <input type="hidden" name="vm_id" id="editVmId">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" id="editVmName" required>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" id="editVmVcpu" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" id="editVmMemory" min="128" step="128">
                </div>
                <div class="form-group">
                    <label>Network</label>
                    <select name="network_id" id="editVmNetwork">
                        <option value="">No network</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Kernel Arguments (optional)</label>
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0,115200n8 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" id="editVmDnsServers" placeholder="8.8.8.8,8.8.4.4">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
                </div>
                <div class="form-group">
                    <label>Snapshot Type (optional)</label>
                    <select name="snapshot_type" id="editVmSnapshotType">
                        <option value="">Disabled</option>
                        <option value="Full">Full Snapshot</option>
                        <option value="Diff">Differential Snapshot</option>
                    </select>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Enable Firecracker snapshot feature for VM state preservation.</small>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="editVmAutorun" style="width: auto; margin-right: 8px;">
                        Autorun
                    </label>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Start this VM automatically when FireCrackManager starts.</small>
                </div>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 10px;">
                    Note: Kernel and RootFS cannot be changed after VM creation.
                </p>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('editVMModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveVM()">Save Changes</button>
        </div>
    </div>
</div>

<div id="snapshotsModal" class="modal">
    <div class="modal-content" style="max-width: 800px;">
        <div class="modal-header">
            <h3>Snapshots - <span id="snapshotsVmName"></span></h3>
            <span class="material-icons modal-close" onclick="closeModal('snapshotsModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="snapshotsVmId">
            <div style="margin-bottom: 15px;">
                <button class="btn btn-primary btn-sm" onclick="createSnapshotFromModal()" id="createSnapshotBtn">
                    <span class="material-icons">add_a_photo</span> Create New Snapshot
                </button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Created At</th>
                        <th>State Size</th>
                        <th>Memory Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="snapshotsList">
                    <tr><td colspan="4">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('snapshotsModal')">Close</button>
        </div>
    </div>
</div>

<!-- Import VM Modal -->
<div id="importVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Import VM</h2>
            <span class="material-icons modal-close" onclick="closeModal('importVMModal')">close</span>
        </div>
        <form id="importVMForm" onsubmit="submitImportVM(event)">
            <div class="form-group">
                <label>VM Name</label>
                <input type="text" name="name" id="importVmName" required placeholder="Enter VM name">
            </div>
            <div class="form-group">
                <label>Kernel</label>
                <select name="kernel_id" id="importKernelSelect" required>
                    <option value="">Select a kernel</option>
                </select>
            </div>
            <div class="form-group">
                <label>.fcrack File</label>
                <input type="file" name="file" id="importVmFile" accept=".fcrack" required>
                <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Select a .fcrack virtual appliance file to import.</small>
            </div>
            <div id="importProgress" style="display: none; margin-top: 10px;">
                <div style="background: var(--bg-tertiary); border-radius: 4px; overflow: hidden;">
                    <div id="importProgressBar" style="background: var(--primary); height: 4px; width: 0%; transition: width 0.3s;"></div>
                </div>
                <small id="importProgressText" style="color: var(--text-secondary);">Uploading...</small>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('importVMModal')">Cancel</button>
                <button type="submit" class="btn btn-primary" id="importVmSubmit">Import</button>
            </div>
        </form>
    </div>
</div>

<!-- Duplicate VM Modal -->
<div id="duplicateVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Duplicate VM</h2>
            <span class="material-icons modal-close" onclick="closeModal('duplicateVMModal')" id="duplicateModalClose">close</span>
        </div>
        <form id="duplicateVMForm" onsubmit="submitDuplicateVM(event)">
            <input type="hidden" name="vm_id" id="duplicateVmId">
            <div class="form-group">
                <label>Original VM</label>
                <input type="text" id="duplicateVmOriginal" disabled>
            </div>
            <div class="form-group">
                <label>New VM Name</label>
                <input type="text" name="name" id="duplicateVmName" required placeholder="Enter new VM name">
            </div>
            <div id="duplicateProgress" style="display: none; margin-top: 15px;">
                <div style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                    <span id="duplicateProgressStage" style="color: var(--text-secondary); font-size: 13px;">Initializing...</span>
                    <span id="duplicateProgressPercent" style="color: var(--primary); font-weight: 500;">0%</span>
                </div>
                <div style="background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; height: 8px;">
                    <div id="duplicateProgressBar" style="background: var(--primary); height: 100%; width: 0%; transition: width 0.3s ease;"></div>
                </div>
                <div style="margin-top: 8px; display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary);">
                    <span id="duplicateProgressCopied">0 MB</span>
                    <span id="duplicateProgressTotal">0 MB</span>
                </div>
            </div>
            <div class="modal-footer" id="duplicateFormFooter">
                <button type="button" class="btn btn-secondary" onclick="closeModal('duplicateVMModal')">Cancel</button>
                <button type="submit" class="btn btn-primary" id="duplicateSubmitBtn">Duplicate</button>
            </div>
        </form>
    </div>
</div>

<!-- Move to VM Group Modal -->
<div id="moveToGroupModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Move to VM Group</h2>
            <span class="material-icons modal-close" onclick="closeModal('moveToGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="moveToGroupVmId">
            <div class="form-group">
                <label>VM</label>
                <input type="text" id="moveToGroupVmName" disabled>
            </div>
            <div class="form-group">
                <label>Current Group</label>
                <input type="text" id="moveToGroupCurrentGroup" disabled value="None">
            </div>
            <div class="form-group">
                <label>Select VM Group</label>
                <select id="moveToGroupSelect">
                    <option value="">-- Select a group --</option>
                </select>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('moveToGroupModal')">Cancel</button>
            <button type="button" class="btn btn-danger" onclick="removeFromCurrentGroup()" id="removeFromGroupBtn" style="display: none;">Remove from Group</button>
            <button type="button" class="btn btn-primary" onclick="submitMoveToGroup()">Move</button>
        </div>
    </div>
</div>

<!-- Disks Modal -->
<div id="disksModal" class="modal">
    <div class="modal-content" style="max-width: 700px;">
        <div class="modal-header">
            <h2>Manage Disks - <span id="disksVmName"></span></h2>
            <span class="material-icons modal-close" onclick="closeModal('disksModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="disksVmId">

            <!-- Add Disk Form -->
            <div style="background: var(--bg-tertiary); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h4 style="margin-bottom: 15px;">Attach New Disk</h4>
                <form id="attachDiskForm" onsubmit="submitAttachDisk(event)" style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 10px; align-items: end;">
                    <div class="form-group" style="margin: 0;">
                        <label>Name</label>
                        <input type="text" name="name" id="diskName" required placeholder="data-disk">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label>Size (MB)</label>
                        <input type="number" name="size_mb" id="diskSizeMB" required min="10" value="1024" placeholder="1024">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label>Mount Point</label>
                        <input type="text" name="mount_point" id="diskMountPoint" required placeholder="/mnt/data">
                    </div>
                    <button type="submit" class="btn btn-primary" style="height: 38px;">
                        <span class="material-icons">add</span>
                        Attach
                    </button>
                </form>
            </div>

            <!-- Disks List -->
            <h4 style="margin-bottom: 10px;">Attached Disks</h4>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Mount Point</th>
                        <th>Device</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="disksList">
                    <tr><td colspan="5">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('disksModal')">Close</button>
        </div>
    </div>
</div>

<!-- Networks Modal -->
<div id="networksModal" class="modal">
    <div class="modal-content" style="max-width: 700px;">
        <div class="modal-header">
            <h2>Manage Networks - <span id="networksVmName"></span></h2>
            <span class="material-icons modal-close" onclick="closeModal('networksModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="networksVmId">

            <!-- Add Network Form -->
            <div style="background: var(--bg-tertiary); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h4 style="margin-bottom: 15px;">Add Network Interface</h4>
                <form id="attachNetworkForm" onsubmit="submitAttachNetwork(event)" style="display: grid; grid-template-columns: 2fr 1fr auto; gap: 10px; align-items: end;">
                    <div class="form-group" style="margin: 0;">
                        <label>Network</label>
                        <select name="network_id" id="networkSelectForVm" required>
                            <option value="">Select a network</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label>IP Address (Optional)</label>
                        <input type="text" name="ip_address" id="networkIpAddress" placeholder="Auto">
                    </div>
                    <button type="submit" class="btn btn-primary" style="height: 38px;">
                        <span class="material-icons">add</span>
                        Add
                    </button>
                </form>
            </div>

            <!-- Networks List -->
            <h4 style="margin-bottom: 10px;">Network Interfaces</h4>
            <table>
                <thead>
                    <tr>
                        <th>Interface</th>
                        <th>Network</th>
                        <th>MAC Address</th>
                        <th>IP Address</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="networksList">
                    <tr><td colspan="5">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('networksModal')">Close</button>
        </div>
    </div>
</div>

<!-- Change Password Modal -->
<div id="changePasswordModal" class="modal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h2>Change Root Password</h2>
            <span class="material-icons modal-close" onclick="closeModal('changePasswordModal')">close</span>
        </div>
        <form id="changePasswordForm" onsubmit="submitChangePassword(event)">
            <input type="hidden" name="vm_id" id="changePasswordVmId">
            <div class="form-group">
                <label>VM</label>
                <input type="text" id="changePasswordVmName" disabled>
            </div>
            <div class="form-group">
                <label>New Root Password</label>
                <input type="password" name="password" id="changePasswordInput" required minlength="1" placeholder="Enter new root password">
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" id="changePasswordConfirm" required minlength="1" placeholder="Confirm new password">
            </div>
            <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">
                This will change the root password in the VM's root filesystem.
                The VM must be stopped.
            </small>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('changePasswordModal')">Cancel</button>
                <button type="submit" class="btn btn-primary" id="changePasswordSubmit">Change Password</button>
            </div>
        </form>
    </div>
</div>

<!-- Expand Disk Modal -->
<div id="expandDiskModal" class="modal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h2>Expand Disk</h2>
            <span class="material-icons modal-close" onclick="closeModal('expandDiskModal')">close</span>
        </div>
        <form id="expandDiskForm" onsubmit="submitExpandDisk(event)">
            <input type="hidden" id="expandDiskVmId">
            <input type="hidden" id="expandDiskId">
            <input type="hidden" id="expandDiskCurrentSizeMB">
            <div class="form-group">
                <label>Disk Name</label>
                <span id="expandDiskName" style="font-weight: bold;"></span>
            </div>
            <div class="form-group">
                <label>Current Size</label>
                <span id="expandDiskCurrentSize" style="font-weight: bold;"></span>
            </div>
            <div class="form-group">
                <label>New Size (MB)</label>
                <input type="number" id="expandDiskNewSize" required min="1" step="1" placeholder="Size in MB">
            </div>
            <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">
                The VM must be stopped to expand the disk. The disk can only be expanded (not shrunk).
            </small>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('expandDiskModal')">Cancel</button>
                <button type="submit" class="btn btn-info"><span class="material-icons">expand</span> Expand Disk</button>
            </div>
        </form>
    </div>
</div>

<!-- Expand RootFS Modal -->
<div id="expandRootFSModal" class="modal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h2>Expand Root Filesystem</h2>
            <span class="material-icons modal-close" onclick="closeModal('expandRootFSModal')">close</span>
        </div>
        <form id="expandRootFSForm" onsubmit="submitExpandRootFS(event)">
            <input type="hidden" id="expandRootFSVmId">
            <input type="hidden" id="expandRootFSCurrentSizeMB">
            <div class="form-group">
                <label>VM</label>
                <span id="expandRootFSVmName" style="font-weight: bold;"></span>
            </div>
            <div class="form-group">
                <label>Current Size</label>
                <span id="expandRootFSCurrentSize" style="font-weight: bold;"></span>
            </div>
            <div class="form-group">
                <label>New Size (MB)</label>
                <input type="number" id="expandRootFSNewSize" required min="1" step="1" placeholder="Size in MB">
            </div>
            <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">
                The VM must be stopped to expand the root filesystem. The filesystem can only be expanded (not shrunk).
            </small>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('expandRootFSModal')">Cancel</button>
                <button type="submit" class="btn btn-info"><span class="material-icons">expand</span> Expand RootFS</button>
            </div>
        </form>
    </div>
</div>

<script>
let openMenuVmId = null;
let searchTimeout = null;
let isSearchActive = false;
let currentViewMode = 'list'; // 'list' or 'group'
let cachedVMs = [];
let cachedVMGroups = [];

// View switching
function switchToListView() {
    currentViewMode = 'list';
    document.getElementById('listViewBtn').classList.add('active');
    document.getElementById('groupViewBtn').classList.remove('active');
    document.getElementById('vmListView').style.display = 'block';
    document.getElementById('vmGroupView').style.display = 'none';
    loadVMs();
}

function switchToGroupView() {
    currentViewMode = 'group';
    document.getElementById('listViewBtn').classList.remove('active');
    document.getElementById('groupViewBtn').classList.add('active');
    document.getElementById('vmListView').style.display = 'none';
    document.getElementById('vmGroupView').style.display = 'block';
    loadVMGroupedView();
}

async function loadVMGroupedView() {
    const treeContainer = document.getElementById('vmGroupTree');
    treeContainer.innerHTML = '<div class="loading">Loading...</div>';

    // Load all VMs
    const { ok: vmsOk, data: vmsData } = await apiCall('/api/vms');
    if (!vmsOk) {
        treeContainer.innerHTML = '<div class="error">Failed to load VMs</div>';
        return;
    }
    cachedVMs = vmsData.vms || [];

    // Load all VM groups
    const { ok: groupsOk, data: groupsData } = await apiCall('/api/vmgroups');
    cachedVMGroups = (groupsOk && groupsData.vm_groups) ? groupsData.vm_groups : [];

    // Get VMs for each group
    const groupedVMs = {};
    const assignedVMIds = new Set();

    for (const group of cachedVMGroups) {
        const { ok, data } = await apiCall(` + "`" + `/api/vmgroups/${group.id}/vms` + "`" + `);
        if (ok && data.vms) {
            groupedVMs[group.id] = data.vms;
            data.vms.forEach(vm => assignedVMIds.add(vm.id));
        } else {
            groupedVMs[group.id] = [];
        }
    }

    // Find unassigned VMs
    const unassignedVMs = cachedVMs.filter(vm => !assignedVMIds.has(vm.id));

    // Render tree
    renderVMGroupTree(cachedVMGroups, groupedVMs, unassignedVMs);
}

function renderVMGroupTree(groups, groupedVMs, unassignedVMs) {
    const treeContainer = document.getElementById('vmGroupTree');
    let html = '';

    // Render each group
    for (const group of groups) {
        const vms = groupedVMs[group.id] || [];
        html += renderGroupItem(group.id, group.name, 'folder', vms);
    }

    // Render unassigned VMs
    if (unassignedVMs.length > 0 || groups.length === 0) {
        html += renderGroupItem('unassigned', 'Unassigned', 'folder_off', unassignedVMs);
    }

    if (!html) {
        html = '<div class="empty-state"><span class="material-icons">dns</span><p>No VMs found</p></div>';
    }

    treeContainer.innerHTML = html;
}

function renderGroupItem(groupId, groupName, icon, vms) {
    const vmCount = vms.length;
    const vmsHtml = vms.length > 0
        ? vms.map(vm => renderGroupVM(vm)).join('')
        : '<div class="vm-group-empty">No VMs in this group</div>';

    return ` + "`" + `
        <div class="vm-group-item" data-group-id="${groupId}">
            <div class="vm-group-header" onclick="toggleGroupExpand('${groupId}')">
                <span class="material-icons toggle-icon">expand_more</span>
                <span class="material-icons group-icon">${icon}</span>
                <span class="group-name">${groupName}</span>
                <span class="vm-count">${vmCount} VM${vmCount !== 1 ? 's' : ''}</span>
            </div>
            <div class="vm-group-content" data-group-content="${groupId}">
                ${vmsHtml}
            </div>
        </div>
    ` + "`" + `;
}

function renderGroupVM(vm) {
    const statusClass = vm.status === 'running' ? 'running' : vm.status === 'error' ? 'error' : 'stopped';
    const statusBadge = vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'warning';
    return ` + "`" + `
        <div class="vm-group-vm">
            <span class="material-icons vm-icon ${statusClass}">computer</span>
            <div class="vm-info">
                <div class="vm-name">
                    <a href="/vms/${vm.id}">${vm.name}</a>
                    ${vm.autorun ? '<span class="material-icons" style="font-size: 14px; color: var(--primary); vertical-align: middle; margin-left: 4px;" title="Autorun enabled">auto_mode</span>' : ''}
                </div>
                <div class="vm-details">${vm.vcpu} vCPU · ${vm.memory_mb} MB · ${vm.ip_address || 'No IP'}</div>
            </div>
            <div class="vm-status">
                <span class="badge badge-${statusBadge}">${vm.status}</span>
            </div>
            <div class="vm-actions">
                ${vm.status === 'running'
                    ? ` + "`" + `<button class="btn btn-danger btn-xs" onclick="stopVM('${vm.id}')" title="Stop"><span class="material-icons">stop</span></button>` + "`" + `
                    : ` + "`" + `<button class="btn btn-success btn-xs" onclick="startVM('${vm.id}')" title="Start"><span class="material-icons">play_arrow</span></button>` + "`" + `
                }
            </div>
        </div>
    ` + "`" + `;
}

function toggleGroupExpand(groupId) {
    const item = document.querySelector(` + "`" + `.vm-group-item[data-group-id="${groupId}"]` + "`" + `);
    const header = item.querySelector('.vm-group-header');
    const content = item.querySelector('.vm-group-content');

    header.classList.toggle('collapsed');
    content.classList.toggle('collapsed');
}

// Search functionality
function toggleAdvancedSearch() {
    const panel = document.getElementById('advancedSearchPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

function debounceSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(applySearch, 300);
}

function clearSearch() {
    document.getElementById('vmSearchQuery').value = '';
    document.getElementById('vmFilterStatus').value = '';
    document.getElementById('vmFilterNetwork').value = '';
    document.getElementById('vmFilterVMGroup').value = '';
    document.getElementById('vmFilterOS').value = '';
    isSearchActive = false;
    document.getElementById('searchResultInfo').style.display = 'none';
    loadVMs();
}

async function applySearch() {
    const query = document.getElementById('vmSearchQuery').value.trim();
    const status = document.getElementById('vmFilterStatus').value;
    const networkId = document.getElementById('vmFilterNetwork').value;
    const vmGroupId = document.getElementById('vmFilterVMGroup').value;
    const os = document.getElementById('vmFilterOS').value.trim();

    // If no filters active, use regular load
    if (!query && !status && !networkId && !vmGroupId && !os) {
        isSearchActive = false;
        document.getElementById('searchResultInfo').style.display = 'none';
        loadVMs();
        return;
    }

    isSearchActive = true;

    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (status) params.append('status', status);
    if (networkId) params.append('network_id', networkId);
    if (vmGroupId) params.append('vm_group_id', vmGroupId);
    if (os) params.append('os', os);

    const { ok, data } = await apiCall('/api/vms/search?' + params.toString());
    if (!ok) return;

    const resultInfo = document.getElementById('searchResultInfo');
    resultInfo.style.display = 'block';
    resultInfo.textContent = ` + "`" + `Found ${data.count || 0} VM(s) matching your search` + "`" + `;

    renderVMList(data.vms || []);
}

function getStatusColor(status) {
    if (status === 'running') return 'var(--success)';
    if (status === 'error') return 'var(--danger)';
    return 'var(--warning)';
}

function renderVMList(vms) {
    const tbody = document.getElementById('vmList');
    if (!vms || vms.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><span class="material-icons">search_off</span><p>No VMs found</p></td></tr>';
        return;
    }

    tbody.innerHTML = vms.map(vmData => {
        const vm = vmData.vm || vmData;
        const osInfo = vmData.os_release ? ` + "`" + ` <small style="color: var(--text-secondary);">(${vmData.os_release})</small>` + "`" + ` : '';
        const statusColor = getStatusColor(vm.status);
        return ` + "`" + `
        <tr>
            <td>
                <span class="material-icons" style="font-size: 18px; color: ${statusColor}; vertical-align: middle; margin-right: 6px;">computer</span>
                <a href="/vms/${vm.id}">${vm.name}</a>${osInfo}
                ${vm.autorun ? '<span class="material-icons" style="font-size: 14px; color: var(--primary); vertical-align: middle; margin-left: 4px;" title="Autorun enabled">auto_mode</span>' : ''}
            </td>
            <td>${vm.vcpu}</td>
            <td>${vm.memory_mb} MB</td>
            <td>
                <span class="badge badge-${vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'warning'}">
                    ${vm.status}
                </span>
            </td>
            <td>${vm.ip_address || '-'}</td>
            <td>-</td>
            <td class="actions">
                <div class="action-menu">
                    <button class="btn btn-primary btn-sm action-menu-btn" onclick="toggleActionMenu('${vm.id}', event)">
                        <span class="material-icons">more_vert</span>
                        Actions
                    </button>
                    <div class="action-dropdown" id="action-menu-${vm.id}">
                        ${vm.status === 'running'
                            ? ` + "`" + `<button class="action-dropdown-item danger" onclick="stopVM('${vm.id}'); closeAllMenus();">
                                <span class="material-icons">stop</span> Stop VM
                               </button>` + "`" + `
                            : ` + "`" + `<button class="action-dropdown-item success" onclick="startVM('${vm.id}'); closeAllMenus();">
                                <span class="material-icons">play_arrow</span> Start VM
                               </button>` + "`" + `
                        }
                        <button class="action-dropdown-item" onclick="openVMConsole('${vm.id}'); closeAllMenus();" ${vm.status !== 'running' ? 'disabled' : ''}>
                            <span class="material-icons">terminal</span> Console
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item" onclick="editVM('${vm.id}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">edit</span> Edit
                        </button>
                        <button class="action-dropdown-item danger" onclick="deleteVM('${vm.id}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">delete</span> Delete VM
                        </button>
                    </div>
                </div>
            </td>
        </tr>
    ` + "`" + `}).join('');
}

async function loadSearchFilters() {
    // Load networks
    const { ok: netOk, data: netData } = await apiCall('/api/networks');
    if (netOk && netData.networks) {
        const networkSelect = document.getElementById('vmFilterNetwork');
        netData.networks.forEach(n => {
            networkSelect.innerHTML += ` + "`" + `<option value="${n.id}">${n.name}</option>` + "`" + `;
        });
    }

    // Load VM groups
    const { ok: groupOk, data: groupData } = await apiCall('/api/vmgroups');
    if (groupOk && groupData.vm_groups) {
        const groupSelect = document.getElementById('vmFilterVMGroup');
        groupData.vm_groups.forEach(g => {
            groupSelect.innerHTML += ` + "`" + `<option value="${g.id}">${g.name}</option>` + "`" + `;
        });
    }
}

async function loadVMs() {
    // Skip refresh if search is active or action menu is open
    if (isSearchActive || openMenuVmId !== null) {
        return;
    }

    const { ok, data } = await apiCall('/api/vms');
    if (!ok) return;

    const tbody = document.getElementById('vmList');
    if (!data.vms || data.vms.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><span class="material-icons">memory</span><p>No virtual machines</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.vms.map(vm => ` + "`" + `
        <tr>
            <td>
                <a href="/vms/${vm.id}">${vm.name}</a>
                ${vm.autorun ? '<span class="material-icons" style="font-size: 14px; color: var(--primary); vertical-align: middle; margin-left: 4px;" title="Autorun enabled">auto_mode</span>' : ''}
            </td>
            <td>${vm.vcpu}</td>
            <td>${vm.memory_mb} MB</td>
            <td>
                <span class="badge badge-${vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'warning'}">
                    ${vm.status}
                </span>
            </td>
            <td>${vm.ip_address || '-'}</td>
            <td id="ping-${vm.id}">
                ${vm.ip_address && vm.status === 'running'
                    ? '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite;">sync</span>'
                    : '-'}
            </td>
            <td class="actions">
                <div class="action-menu">
                    <button class="btn btn-primary btn-sm action-menu-btn" onclick="toggleActionMenu('${vm.id}', event)">
                        <span class="material-icons">more_vert</span>
                        Actions
                    </button>
                    <div class="action-dropdown" id="action-menu-${vm.id}">
                        ${vm.status === 'running'
                            ? ` + "`" + `<button class="action-dropdown-item danger" onclick="stopVM('${vm.id}'); closeAllMenus();">
                                <span class="material-icons">stop</span> Stop VM
                               </button>` + "`" + `
                            : ` + "`" + `<button class="action-dropdown-item success" onclick="startVM('${vm.id}'); closeAllMenus();">
                                <span class="material-icons">play_arrow</span> Start VM
                               </button>` + "`" + `
                        }
                        <button class="action-dropdown-item" onclick="openVMConsole('${vm.id}'); closeAllMenus();" ${vm.status !== 'running' ? 'disabled' : ''}>
                            <span class="material-icons">terminal</span> Console
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item" onclick="editVM('${vm.id}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">edit</span> Edit
                        </button>
                        <button class="action-dropdown-item" onclick="openChangePasswordModal('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">key</span> Change Password
                        </button>
                        <button class="action-dropdown-item" onclick="createSnapshot('${vm.id}'); closeAllMenus();" ${vm.status !== 'running' || !vm.snapshot_type ? 'disabled' : ''}>
                            <span class="material-icons">photo_camera</span> Snapshots
                        </button>
                        <button class="action-dropdown-item" onclick="openDisksModal('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">storage</span> Disks
                        </button>
                        <button class="action-dropdown-item" onclick="openNetworksModal('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">lan</span> Networks
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item" onclick="duplicateVM('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">content_copy</span> Duplicate
                        </button>
                        <button class="action-dropdown-item" onclick="exportVM('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">download</span> Export
                        </button>
                        <button class="action-dropdown-item" onclick="openMoveToGroupModal('${vm.id}', '${vm.name}'); closeAllMenus();">
                            <span class="material-icons">folder_special</span> Move to Group
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item danger" onclick="deleteVM('${vm.id}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">delete</span> Delete
                        </button>
                    </div>
                </div>
            </td>
        </tr>
    ` + "`" + `).join('');

    // Check reachability for running VMs with IP addresses
    for (const vm of data.vms) {
        if (vm.ip_address && vm.status === 'running') {
            checkVMReachability(vm.id, vm.ip_address);
        }
    }
}

async function checkVMReachability(vmId, ip) {
    const cell = document.getElementById('ping-' + vmId);
    if (!cell) return;

    try {
        const { ok, data } = await apiCall('/api/ping/' + ip);
        if (ok) {
            if (data.reachable) {
                cell.innerHTML = '<span class="badge badge-success">Reachable</span>';
            } else {
                cell.innerHTML = '<span class="badge badge-secondary">Unreachable</span>';
            }
        } else {
            cell.innerHTML = '<span class="badge badge-secondary">Unknown</span>';
        }
    } catch (e) {
        cell.innerHTML = '<span class="badge badge-secondary">Error</span>';
    }
}

async function loadFormData() {
    const kernels = await apiCall('/api/kernels');
    if (kernels.ok && kernels.data.kernels) {
        const select = document.getElementById('kernelSelect');
        kernels.data.kernels.forEach(k => {
            select.innerHTML += ` + "`" + `<option value="${k.id}">${k.name} (${k.version})</option>` + "`" + `;
        });
    }

    const rootfs = await apiCall('/api/rootfs');
    if (rootfs.ok && rootfs.data.rootfs) {
        const rootfsSelect = document.getElementById('rootfsSelect');
        const dataDiskSelect = document.getElementById('dataDiskSelect');
        rootfs.data.rootfs.forEach(r => {
            // Only system disks can be used as root filesystem
            if (r.disk_type === 'system' || !r.disk_type) {
                rootfsSelect.innerHTML += ` + "`" + `<option value="${r.id}">${r.name}</option>` + "`" + `;
            }
            // Only data disks can be attached as additional disks
            if (r.disk_type === 'data') {
                dataDiskSelect.innerHTML += ` + "`" + `<option value="${r.id}">${r.name} (${formatBytes(r.size)})</option>` + "`" + `;
            }
        });
    }

    const networks = await apiCall('/api/networks');
    if (networks.ok && networks.data.networks) {
        const select = document.getElementById('networkSelect');
        networks.data.networks.forEach(n => {
            select.innerHTML += ` + "`" + `<option value="${n.id}">${n.name} (${n.subnet})</option>` + "`" + `;
        });
    }
}

async function createVM() {
    const form = document.getElementById('createVMForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        vcpu: parseInt(formData.get('vcpu')) || 1,
        memory_mb: parseInt(formData.get('memory_mb')) || 512,
        kernel_id: formData.get('kernel_id'),
        rootfs_id: formData.get('rootfs_id'),
        network_id: formData.get('network_id') || '',
        kernel_args: formData.get('kernel_args') || '',
        dns_servers: formData.get('dns_servers') || '',
        snapshot_type: formData.get('snapshot_type') || '',
        data_disk_id: formData.get('data_disk_id') || ''
    };

    const { ok, data: resp } = await apiCall('/api/vms', 'POST', data);
    if (ok) {
        closeModal('createVMModal');
        form.reset();
        loadVMs();
    } else {
        alert(resp.error || 'Failed to create VM');
    }
}

function toggleActionMenu(vmId, event) {
    event.stopPropagation();
    const menu = document.getElementById('action-menu-' + vmId);
    const wasOpen = menu.classList.contains('show');
    closeAllMenus();
    if (!wasOpen) {
        menu.classList.add('show');
        openMenuVmId = vmId;
    }
}

function closeAllMenus() {
    document.querySelectorAll('.action-dropdown').forEach(menu => {
        menu.classList.remove('show');
    });
    openMenuVmId = null;
}

// Close menus when clicking outside
document.addEventListener('click', function(event) {
    if (!event.target.closest('.action-menu')) {
        closeAllMenus();
    }
});

async function startVM(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}/start` + "`" + `, 'POST');
    if (ok) {
        loadVMs();
    } else {
        alert(data.error || 'Failed to start VM');
    }
}

async function stopVM(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}/stop` + "`" + `, 'POST');
    if (ok) {
        loadVMs();
    } else {
        alert(data.error || 'Failed to stop VM');
    }
}

async function deleteVM(id) {
    if (!confirm('Are you sure you want to delete this VM?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadVMs();
    } else {
        alert(data.error || 'Failed to delete VM');
    }
}

function openVMConsole(id) {
    window.open('/console/' + id, '_blank', 'width=1000,height=700');
}

async function editVM(id) {
    // Fetch VM details
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}` + "`" + `);
    if (!ok) {
        alert(data.error || 'Failed to load VM');
        return;
    }

    // Populate edit form
    document.getElementById('editVmId').value = data.id;
    document.getElementById('editVmName').value = data.name;
    document.getElementById('editVmVcpu').value = data.vcpu;
    document.getElementById('editVmMemory').value = data.memory_mb;
    document.getElementById('editVmKernelArgs').value = data.kernel_args || '';
    document.getElementById('editVmDnsServers').value = data.dns_servers || '';
    document.getElementById('editVmSnapshotType').value = data.snapshot_type || '';
    document.getElementById('editVmAutorun').checked = data.autorun || false;

    // Load networks for the dropdown
    const editNetworkSelect = document.getElementById('editVmNetwork');
    editNetworkSelect.innerHTML = '<option value="">No network</option>';
    const networks = await apiCall('/api/networks');
    if (networks.ok && networks.data.networks) {
        networks.data.networks.forEach(n => {
            const selected = n.id === data.network_id ? 'selected' : '';
            editNetworkSelect.innerHTML += ` + "`" + `<option value="${n.id}" ${selected}>${n.name} (${n.subnet})</option>` + "`" + `;
        });
    }

    openModal('editVMModal');
}

async function saveVM() {
    const vmId = document.getElementById('editVmId').value;
    const updateData = {
        name: document.getElementById('editVmName').value,
        vcpu: parseInt(document.getElementById('editVmVcpu').value) || 1,
        memory_mb: parseInt(document.getElementById('editVmMemory').value) || 512,
        network_id: document.getElementById('editVmNetwork').value,
        kernel_args: document.getElementById('editVmKernelArgs').value,
        dns_servers: document.getElementById('editVmDnsServers').value,
        snapshot_type: document.getElementById('editVmSnapshotType').value,
        autorun: document.getElementById('editVmAutorun').checked
    };

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}` + "`" + `, 'PUT', updateData);
    if (ok) {
        closeModal('editVMModal');
        loadVMs();
    } else {
        alert(data.error || 'Failed to update VM');
    }
}

async function createSnapshot(id) {
    // Open snapshots modal instead of creating directly
    await openSnapshotsModal(id);
}

async function openSnapshotsModal(vmId) {
    // Fetch VM details for the name
    const { ok: vmOk, data: vmData } = await apiCall(` + "`" + `/api/vms/${vmId}` + "`" + `);
    if (!vmOk) {
        alert(vmData.error || 'Failed to load VM');
        return;
    }

    document.getElementById('snapshotsVmId').value = vmId;
    document.getElementById('snapshotsVmName').textContent = vmData.name;

    // Enable/disable create button based on VM status
    const createBtn = document.getElementById('createSnapshotBtn');
    if (vmData.status === 'running' && vmData.snapshot_type) {
        createBtn.disabled = false;
        createBtn.classList.remove('btn-secondary');
        createBtn.classList.add('btn-primary');
    } else {
        createBtn.disabled = true;
        createBtn.classList.remove('btn-primary');
        createBtn.classList.add('btn-secondary');
    }

    openModal('snapshotsModal');
    await loadSnapshots(vmId);
}

async function loadSnapshots(vmId) {
    const tbody = document.getElementById('snapshotsList');
    tbody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/snapshot` + "`" + `);
    if (!ok) {
        tbody.innerHTML = '<tr><td colspan="4">Failed to load snapshots</td></tr>';
        return;
    }

    if (!data.snapshots || data.snapshots.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><span class="material-icons">photo_camera</span><p>No snapshots yet</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.snapshots.map(s => ` + "`" + `
        <tr>
            <td>${s.created_at}</td>
            <td>${formatBytes(s.state_size)}</td>
            <td>${formatBytes(s.mem_size)}</td>
            <td class="actions">
                <button class="btn btn-success btn-xs" onclick="restoreSnapshot('${vmId}', '${s.id}')" title="Restore">
                    <span class="material-icons">restore</span>
                </button>
                <button class="btn btn-danger btn-xs" onclick="deleteSnapshot('${vmId}', '${s.id}')" title="Delete">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function createSnapshotFromModal() {
    const vmId = document.getElementById('snapshotsVmId').value;
    if (!confirm('Create a snapshot of this VM? This will pause the VM briefly.')) return;

    const btn = document.getElementById('createSnapshotBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Creating...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/snapshot` + "`" + `, 'POST');

    btn.disabled = false;
    btn.innerHTML = '<span class="material-icons">add_a_photo</span> Create New Snapshot';

    if (ok) {
        await loadSnapshots(vmId);
        loadVMs();
    } else {
        alert(data.error || 'Failed to create snapshot');
    }
}

async function restoreSnapshot(vmId, snapshotId) {
    if (!confirm('Restore VM from this snapshot? The current VM state will be lost and replaced with the snapshot state.')) return;

    const tbody = document.getElementById('snapshotsList');
    tbody.innerHTML = '<tr><td colspan="4">Restoring snapshot...</td></tr>';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/snapshots/${snapshotId}/restore` + "`" + `, 'POST');
    if (ok) {
        closeModal('snapshotsModal');
        loadVMs();
        alert('VM restored from snapshot successfully!');
    } else {
        await loadSnapshots(vmId);
        alert(data.error || 'Failed to restore snapshot');
    }
}

async function deleteSnapshot(vmId, snapshotId) {
    if (!confirm('Delete this snapshot? This action cannot be undone.')) return;

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/snapshots/${snapshotId}` + "`" + `, 'DELETE');
    if (ok) {
        await loadSnapshots(vmId);
    } else {
        alert(data.error || 'Failed to delete snapshot');
    }
}

// Duplicate VM functionality
function duplicateVM(vmId, vmName) {
    document.getElementById('duplicateVmId').value = vmId;
    document.getElementById('duplicateVmOriginal').value = vmName;
    document.getElementById('duplicateVmName').value = vmName + '-copy';
    openModal('duplicateVMModal');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function submitDuplicateVM(event) {
    event.preventDefault();
    const vmId = document.getElementById('duplicateVmId').value;
    const name = document.getElementById('duplicateVmName').value;

    // Disable form elements and show progress
    const submitBtn = document.getElementById('duplicateSubmitBtn');
    const nameInput = document.getElementById('duplicateVmName');
    const progressDiv = document.getElementById('duplicateProgress');
    const closeBtn = document.getElementById('duplicateModalClose');

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite; font-size: 16px; vertical-align: middle;">sync</span> Duplicating...';
    nameInput.disabled = true;
    closeBtn.style.display = 'none';
    progressDiv.style.display = 'block';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/duplicate` + "`" + `, 'POST', { name });

    if (!ok) {
        // Reset form on error
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Duplicate';
        nameInput.disabled = false;
        closeBtn.style.display = '';
        progressDiv.style.display = 'none';
        alert(data.error || 'Failed to start VM duplication');
        return;
    }

    // Start polling for progress
    const progressKey = data.progress_key;
    const pollProgress = async () => {
        const { ok: pollOk, data: pollData } = await apiCall(` + "`" + `/api/operations/${progressKey}` + "`" + `, 'GET');

        if (!pollOk || pollData.status === 'not_found') {
            // Operation not found, might have completed quickly
            setTimeout(pollProgress, 500);
            return;
        }

        // Update progress UI
        const percent = Math.round(pollData.percent || 0);
        document.getElementById('duplicateProgressBar').style.width = percent + '%';
        document.getElementById('duplicateProgressPercent').textContent = percent + '%';
        document.getElementById('duplicateProgressStage').textContent = pollData.stage || 'Processing...';
        document.getElementById('duplicateProgressCopied').textContent = formatBytes(pollData.copied || 0);
        document.getElementById('duplicateProgressTotal').textContent = formatBytes(pollData.total || 0);

        if (pollData.status === 'completed') {
            // Success - close modal and refresh
            setTimeout(() => {
                closeModal('duplicateVMModal');
                loadVMs();
                // Reset form for next use
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Duplicate';
                nameInput.disabled = false;
                nameInput.value = '';
                closeBtn.style.display = '';
                progressDiv.style.display = 'none';
                document.getElementById('duplicateProgressBar').style.width = '0%';
            }, 500);
            return;
        } else if (pollData.status === 'error') {
            // Error - show message and reset form
            alert('Duplication failed: ' + (pollData.error || 'Unknown error'));
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Duplicate';
            nameInput.disabled = false;
            closeBtn.style.display = '';
            progressDiv.style.display = 'none';
            document.getElementById('duplicateProgressBar').style.width = '0%';
            return;
        }

        // Continue polling
        setTimeout(pollProgress, 300);
    };

    // Start polling after a small delay
    setTimeout(pollProgress, 200);
}

// Export VM functionality
async function exportVM(vmId, vmName) {
    if (!confirm(` + "`" + `Export VM "${vmName}" as a .fcrack virtual appliance?` + "`" + `)) return;

    // Show loading indicator
    const btn = event.target.closest('button');
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>';
    btn.disabled = true;

    try {
        const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/export` + "`" + `, 'POST');
        if (ok && data.download_url) {
            // Trigger download
            const link = document.createElement('a');
            link.href = data.download_url;
            link.download = data.filename || (vmName + '.fcrack');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            alert('VM export started. Download will begin shortly.');
        } else {
            alert(data.error || 'Failed to export VM');
        }
    } catch (e) {
        alert('Failed to export VM: ' + e.message);
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

// Move to VM Group functionality
let currentMoveVmId = null;
let currentMoveVmGroupId = null;

async function openMoveToGroupModal(vmId, vmName) {
    currentMoveVmId = vmId;
    document.getElementById('moveToGroupVmId').value = vmId;
    document.getElementById('moveToGroupVmName').value = vmName;

    // Load available VM groups
    const { ok, data } = await apiCall('/api/vmgroups');
    const select = document.getElementById('moveToGroupSelect');
    select.innerHTML = '<option value="">-- No Group --</option>';

    if (ok && data.vm_groups) {
        data.vm_groups.forEach(g => {
            select.innerHTML += ` + "`" + `<option value="${g.id}">${g.name}</option>` + "`" + `;
        });
    }

    // Check if VM is already in a group
    await checkVMCurrentGroup(vmId);

    openModal('moveToGroupModal');
}

async function openMoveToGroupModalDetail() {
    const vmId = document.getElementById('vmId').textContent;
    const vmName = document.getElementById('vmName').textContent;
    await openMoveToGroupModal(vmId, vmName);
}

async function checkVMCurrentGroup(vmId) {
    // Check all groups to find if VM is in one
    const { ok, data } = await apiCall('/api/vmgroups');
    const removeBtn = document.getElementById('removeFromGroupBtn');
    const currentGroupField = document.getElementById('moveToGroupCurrentGroup');

    currentMoveVmGroupId = null;
    currentGroupField.value = 'None';
    removeBtn.style.display = 'none';

    if (!ok || !data.vm_groups) return;

    for (const group of data.vm_groups) {
        const vmsResp = await apiCall(` + "`" + `/api/vmgroups/${group.id}/vms` + "`" + `);
        if (vmsResp.ok && vmsResp.data.vms) {
            const vmInGroup = vmsResp.data.vms.find(v => v.id === vmId);
            if (vmInGroup) {
                currentMoveVmGroupId = group.id;
                currentGroupField.value = group.name;
                removeBtn.style.display = 'inline-block';
                document.getElementById('moveToGroupSelect').value = group.id;
                break;
            }
        }
    }
}

async function submitMoveToGroup() {
    const vmId = document.getElementById('moveToGroupVmId').value;
    const newGroupId = document.getElementById('moveToGroupSelect').value;

    // If same group, just close
    if (newGroupId === currentMoveVmGroupId) {
        closeModal('moveToGroupModal');
        return;
    }

    // Remove from current group if exists
    if (currentMoveVmGroupId) {
        const { ok, data } = await apiCall(` + "`" + `/api/vmgroups/${currentMoveVmGroupId}/vms/${vmId}` + "`" + `, 'DELETE');
        if (!ok) {
            alert(data.error || 'Failed to remove VM from current group');
            return;
        }
    }

    // Add to new group if selected
    if (newGroupId) {
        const { ok, data } = await apiCall(` + "`" + `/api/vmgroups/${newGroupId}/vms` + "`" + `, 'POST', { vm_id: vmId });
        if (!ok) {
            alert(data.error || 'Failed to add VM to group');
            return;
        }
    }

    closeModal('moveToGroupModal');

    // Refresh the page data
    if (typeof loadVMs === 'function') {
        loadVMs();
    }
    if (typeof loadVMDetails === 'function') {
        loadVMDetails();
    }

    alert(newGroupId ? 'VM moved to group successfully' : 'VM removed from group successfully');
}

async function removeFromCurrentGroup() {
    const vmId = document.getElementById('moveToGroupVmId').value;

    if (!currentMoveVmGroupId) {
        alert('VM is not in any group');
        return;
    }

    const { ok, data } = await apiCall(` + "`" + `/api/vmgroups/${currentMoveVmGroupId}/vms/${vmId}` + "`" + `, 'DELETE');
    if (ok) {
        closeModal('moveToGroupModal');
        if (typeof loadVMs === 'function') {
            loadVMs();
        }
        if (typeof loadVMDetails === 'function') {
            loadVMDetails();
        }
        alert('VM removed from group successfully');
    } else {
        alert(data.error || 'Failed to remove VM from group');
    }
}

// Import VM functionality
async function openImportModal() {
    // Load kernels for the select
    const { ok, data } = await apiCall('/api/kernels');
    if (ok && data.kernels) {
        const select = document.getElementById('importKernelSelect');
        select.innerHTML = '<option value="">Select a kernel</option>' +
            data.kernels.map(k => ` + "`" + `<option value="${k.id}">${k.name} (${k.version})</option>` + "`" + `).join('');
    }
    document.getElementById('importVMForm').reset();
    document.getElementById('importProgress').style.display = 'none';
    openModal('importVMModal');
}

async function submitImportVM(event) {
    event.preventDefault();

    const form = document.getElementById('importVMForm');
    const formData = new FormData(form);

    const progressDiv = document.getElementById('importProgress');
    const progressBar = document.getElementById('importProgressBar');
    const progressText = document.getElementById('importProgressText');
    const submitBtn = document.getElementById('importVmSubmit');

    progressDiv.style.display = 'block';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Importing...';

    try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/vms/import', true);

        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressBar.style.width = percent + '%';
                progressText.textContent = ` + "`" + `Uploading... ${Math.round(percent)}%` + "`" + `;
            }
        };

        xhr.onload = function() {
            if (xhr.status === 200) {
                const data = JSON.parse(xhr.responseText);
                closeModal('importVMModal');
                loadVMs();
                alert('VM imported successfully!');
            } else {
                let msg = 'Failed to import VM';
                try {
                    const err = JSON.parse(xhr.responseText);
                    msg = err.error || msg;
                } catch (e) {}
                alert(msg);
            }
            submitBtn.disabled = false;
            submitBtn.textContent = 'Import';
        };

        xhr.onerror = function() {
            alert('Failed to import VM: Network error');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Import';
        };

        xhr.send(formData);
    } catch (e) {
        alert('Failed to import VM: ' + e.message);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Import';
    }
}

// Disk management functions
let currentDisksVmId = null;

function openDisksModal(vmId, vmName) {
    currentDisksVmId = vmId;
    document.getElementById('disksVmId').value = vmId;
    document.getElementById('disksVmName').textContent = vmName;
    document.getElementById('attachDiskForm').reset();
    loadDisks(vmId);
    openModal('disksModal');
}

async function loadDisks(vmId) {
    const tbody = document.getElementById('disksList');
    tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/disks` + "`" + `);
    if (!ok) {
        tbody.innerHTML = '<tr><td colspan="5" style="color: var(--danger);">Failed to load disks</td></tr>';
        return;
    }

    if (!data.disks || data.disks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="material-icons">storage</span><p>No additional disks attached</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.disks.map(disk => {
        // Calculate device letter based on drive_id (drive1 -> vdb, drive2 -> vdc, etc.)
        const driveNum = parseInt(disk.drive_id.replace('drive', ''));
        const deviceLetter = String.fromCharCode(97 + driveNum);
        const deviceName = '/dev/vd' + deviceLetter;

        return ` + "`" + `
            <tr>
                <td>${disk.name}</td>
                <td>${formatDiskSize(disk.size_mb)}</td>
                <td><code>${disk.mount_point}</code></td>
                <td><code>${deviceName}</code></td>
                <td>
                    <button class="btn btn-info btn-xs" onclick="openExpandDiskModal('${vmId}', '${disk.id}', '${disk.name}', ${disk.size_mb})" title="Expand Disk">
                        <span class="material-icons">expand</span>
                    </button>
                    <button class="btn btn-danger btn-xs" onclick="detachDisk('${vmId}', '${disk.id}', '${disk.name}')" title="Detach Disk">
                        <span class="material-icons">eject</span>
                    </button>
                </td>
            </tr>
        ` + "`" + `;
    }).join('');
}

function formatDiskSize(sizeMB) {
    if (sizeMB >= 1024) {
        return (sizeMB / 1024).toFixed(1) + ' GB';
    }
    return sizeMB + ' MB';
}

async function submitAttachDisk(event) {
    event.preventDefault();

    const vmId = document.getElementById('disksVmId').value;
    const name = document.getElementById('diskName').value;
    const sizeMB = parseInt(document.getElementById('diskSizeMB').value);
    const mountPoint = document.getElementById('diskMountPoint').value;

    if (!name || !sizeMB || !mountPoint) {
        alert('Please fill in all fields');
        return;
    }

    if (!mountPoint.startsWith('/')) {
        alert('Mount point must be an absolute path (e.g., /mnt/data)');
        return;
    }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Creating...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/disks` + "`" + `, 'POST', {
        name: name,
        size_mb: sizeMB,
        mount_point: mountPoint
    });

    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="material-icons">add</span> Attach';

    if (ok) {
        document.getElementById('attachDiskForm').reset();
        await loadDisks(vmId);
        alert('Disk attached successfully! The disk will be available at ' + mountPoint + ' when the VM starts.');
    } else {
        alert(data.error || 'Failed to attach disk');
    }
}

async function detachDisk(vmId, diskId, diskName) {
    if (!confirm(` + "`" + `Detach disk "${diskName}"? This will permanently delete the disk and all data on it.` + "`" + `)) {
        return;
    }

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/disks/${diskId}` + "`" + `, 'DELETE');
    if (ok) {
        await loadDisks(vmId);
        alert('Disk detached successfully');
    } else {
        alert(data.error || 'Failed to detach disk');
    }
}

// Expand disk functionality
function openExpandDiskModal(vmId, diskId, diskName, currentSizeMB) {
    document.getElementById('expandDiskVmId').value = vmId;
    document.getElementById('expandDiskId').value = diskId;
    document.getElementById('expandDiskName').textContent = diskName;
    document.getElementById('expandDiskCurrentSize').textContent = formatDiskSize(currentSizeMB);
    document.getElementById('expandDiskCurrentSizeMB').value = currentSizeMB;
    document.getElementById('expandDiskNewSize').value = currentSizeMB + 1024; // Default to +1GB
    document.getElementById('expandDiskNewSize').min = currentSizeMB + 1;
    openModal('expandDiskModal');
}

async function submitExpandDisk(event) {
    event.preventDefault();

    const vmId = document.getElementById('expandDiskVmId').value;
    const diskId = document.getElementById('expandDiskId').value;
    const currentSizeMB = parseInt(document.getElementById('expandDiskCurrentSizeMB').value);
    const newSizeMB = parseInt(document.getElementById('expandDiskNewSize').value);

    if (newSizeMB <= currentSizeMB) {
        alert('New size must be greater than current size (' + formatDiskSize(currentSizeMB) + ')');
        return;
    }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Expanding...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/disks/${diskId}/expand` + "`" + `, 'POST', {
        new_size_mb: newSizeMB
    });

    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="material-icons">expand</span> Expand Disk';

    if (ok) {
        closeModal('expandDiskModal');
        await loadDisks(vmId);
        alert('Disk expanded successfully to ' + formatDiskSize(newSizeMB));
    } else {
        alert(data.error || 'Failed to expand disk');
    }
}

// Network management functions
let currentNetworksVmId = null;

async function openNetworksModal(vmId, vmName) {
    currentNetworksVmId = vmId;
    document.getElementById('networksVmId').value = vmId;
    document.getElementById('networksVmName').textContent = vmName;
    document.getElementById('attachNetworkForm').reset();

    // Load available networks into dropdown
    await loadNetworkOptions();
    loadVMNetworks(vmId);
    openModal('networksModal');
}

async function loadNetworkOptions() {
    const select = document.getElementById('networkSelectForVm');
    select.innerHTML = '<option value="">Loading networks...</option>';

    const { ok, data } = await apiCall('/api/networks');
    if (!ok) {
        select.innerHTML = '<option value="">Failed to load networks</option>';
        return;
    }

    const activeNetworks = (data.networks || []).filter(n => n.status === 'active');
    if (activeNetworks.length === 0) {
        select.innerHTML = '<option value="">No active networks available</option>';
        return;
    }

    select.innerHTML = '<option value="">Select a network</option>' +
        activeNetworks.map(n => ` + "`" + `<option value="${n.id}">${n.name} (${n.subnet})</option>` + "`" + `).join('');
}

async function loadVMNetworks(vmId) {
    const tbody = document.getElementById('networksList');
    tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/networks` + "`" + `);
    if (!ok) {
        tbody.innerHTML = '<tr><td colspan="5" style="color: var(--danger);">Failed to load networks</td></tr>';
        return;
    }

    if (!data.networks || data.networks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="material-icons">lan</span><p>No network interfaces configured</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.networks.map(net => ` + "`" + `
        <tr>
            <td><strong>eth${net.iface_index}</strong></td>
            <td>${net.network_name || 'Unknown'}</td>
            <td><code style="font-size: 11px;">${net.mac_address}</code></td>
            <td>${net.ip_address || '<span style="color: var(--text-secondary);">Auto</span>'}</td>
            <td>
                <button class="btn btn-danger btn-xs" onclick="removeVMNetwork('${vmId}', '${net.id}', ${net.iface_index})" title="Remove Network">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function submitAttachNetwork(event) {
    event.preventDefault();

    const vmId = document.getElementById('networksVmId').value;
    const networkId = document.getElementById('networkSelectForVm').value;
    const ipAddress = document.getElementById('networkIpAddress').value;

    if (!networkId) {
        alert('Please select a network');
        return;
    }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Adding...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/networks` + "`" + `, 'POST', {
        network_id: networkId,
        ip_address: ipAddress || ''
    });

    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="material-icons">add</span> Add';

    if (ok) {
        document.getElementById('attachNetworkForm').reset();
        await loadVMNetworks(vmId);
    } else {
        alert(data.error || 'Failed to add network interface');
    }
}

async function removeVMNetwork(vmId, netId, ifaceIndex) {
    if (!confirm(` + "`" + `Remove network interface eth${ifaceIndex}?` + "`" + `)) {
        return;
    }

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/networks/${netId}` + "`" + `, 'DELETE');
    if (ok) {
        await loadVMNetworks(vmId);
    } else {
        alert(data.error || 'Failed to remove network interface');
    }
}

// Expand rootfs functionality
function openExpandRootFSModal(vmId, vmName, currentSizeMB) {
    document.getElementById('expandRootFSVmId').value = vmId;
    document.getElementById('expandRootFSVmName').textContent = vmName;
    document.getElementById('expandRootFSCurrentSize').textContent = formatDiskSize(currentSizeMB);
    document.getElementById('expandRootFSCurrentSizeMB').value = currentSizeMB;
    document.getElementById('expandRootFSNewSize').value = currentSizeMB + 1024; // Default to +1GB
    document.getElementById('expandRootFSNewSize').min = currentSizeMB + 1;
    openModal('expandRootFSModal');
}

async function submitExpandRootFS(event) {
    event.preventDefault();

    const vmId = document.getElementById('expandRootFSVmId').value;
    const currentSizeMB = parseInt(document.getElementById('expandRootFSCurrentSizeMB').value);
    const newSizeMB = parseInt(document.getElementById('expandRootFSNewSize').value);

    if (newSizeMB <= currentSizeMB) {
        alert('New size must be greater than current size (' + formatDiskSize(currentSizeMB) + ')');
        return;
    }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Expanding...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/expand-rootfs` + "`" + `, 'POST', {
        new_size_mb: newSizeMB
    });

    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="material-icons">expand</span> Expand RootFS';

    if (ok) {
        closeModal('expandRootFSModal');
        await loadVMDetails(vmId);
        alert('RootFS expanded successfully to ' + formatDiskSize(newSizeMB));
    } else {
        alert(data.error || 'Failed to expand rootfs');
    }
}

// Change root password functionality
function openChangePasswordModal(vmId, vmName) {
    document.getElementById('changePasswordVmId').value = vmId;
    document.getElementById('changePasswordVmName').value = vmName;
    document.getElementById('changePasswordInput').value = '';
    document.getElementById('changePasswordConfirm').value = '';
    openModal('changePasswordModal');
}

async function submitChangePassword(event) {
    event.preventDefault();

    const vmId = document.getElementById('changePasswordVmId').value;
    const password = document.getElementById('changePasswordInput').value;
    const confirmPassword = document.getElementById('changePasswordConfirm').value;

    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }

    if (password.length < 1) {
        alert('Password cannot be empty');
        return;
    }

    const submitBtn = document.getElementById('changePasswordSubmit');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Changing...';

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/password` + "`" + `, 'POST', { password });

    submitBtn.disabled = false;
    submitBtn.textContent = 'Change Password';

    if (ok) {
        closeModal('changePasswordModal');
        alert('Root password changed successfully!');
    } else {
        alert(data.error || 'Failed to change password');
    }
}

loadVMs();
loadFormData();
loadSearchFilters();
setInterval(loadVMs, 5000);
</script>
`
}

func (wc *WebConsole) renderVMDetailPage(vmID string) string {
	return fmt.Sprintf(`
<!-- ApexCharts -->
<script src="/assets/apexcharts.min.js"></script>

<!-- VM Statistics - Now at the top -->
<div class="card">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">monitoring</span>VM Statistics</h3>
        <div class="actions">
            <button class="btn btn-secondary btn-sm" onclick="openLogsModal()">
                <span class="material-icons">article</span> View Logs
            </button>
        </div>
    </div>
    <div class="card-body">
        <div id="vmStatsOffline" style="display: none; text-align: center; padding: 40px; color: var(--text-secondary);">
            <span class="material-icons" style="font-size: 48px; margin-bottom: 10px;">power_off</span>
            <p>VM is not running. Start the VM to see statistics.</p>
        </div>
        <div id="vmStatsOnline">
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                <div style="background: #1ab394; border-radius: 4px; padding: 15px; display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons" style="font-size: 48px; color: rgba(255,255,255,0.7);">memory</span>
                    <div style="text-align: right; flex: 1;">
                        <p style="font-size: 12px; color: white; margin: 0;">CPU Usage</p>
                        <p style="font-size: 24px; font-weight: 600; color: white; margin: 0;" id="statCpuPercent">-</p>
                    </div>
                </div>
                <div style="background: #f5f5f5; border-radius: 4px; padding: 15px; display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons" style="font-size: 48px; color: #9e9e9e;">developer_board</span>
                    <div style="text-align: right; flex: 1;">
                        <p style="font-size: 12px; color: #757575; margin: 0;">Memory</p>
                        <p style="font-size: 24px; font-weight: 600; color: #333; margin: 0;" id="statMemPercent">-</p>
                        <p style="font-size: 11px; color: #9e9e9e; margin: 0;" id="statMemDetail">- / - MB</p>
                    </div>
                </div>
                <div style="background: #f5f5f5; border-radius: 4px; padding: 15px; display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons" style="font-size: 48px; color: #9e9e9e;">schedule</span>
                    <div style="text-align: right; flex: 1;">
                        <p style="font-size: 12px; color: #757575; margin: 0;">Uptime</p>
                        <p style="font-size: 24px; font-weight: 600; color: #333; margin: 0;" id="statUptime">-</p>
                    </div>
                </div>
                <div style="background: #f5f5f5; border-radius: 4px; padding: 15px; display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons" style="font-size: 48px; color: #9e9e9e;">settings</span>
                    <div style="text-align: right; flex: 1;">
                        <p style="font-size: 12px; color: #757575; margin: 0;">vCPUs / Memory</p>
                        <p style="font-size: 24px; font-weight: 600; color: #333; margin: 0;" id="statConfig">-</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>VM Details</h3>
        <div class="actions">
            <button class="btn btn-success" id="startBtn" onclick="startVM()">
                <span class="material-icons">play_arrow</span> Start
            </button>
            <button class="btn btn-danger" id="stopBtn" onclick="stopVM()">
                <span class="material-icons">stop</span> Stop
            </button>
            <button class="btn btn-primary" id="consoleBtn" onclick="openConsole()">
                <span class="material-icons">terminal</span> Console
            </button>
            <button class="btn btn-secondary" id="editBtn" onclick="openEditModal()">
                <span class="material-icons">edit</span> Edit
            </button>
            <button class="btn btn-secondary" onclick="openMoveToGroupModalDetail()">
                <span class="material-icons">folder_special</span> Move to Group
            </button>
            <button class="btn btn-secondary" onclick="deleteVM()">
                <span class="material-icons">delete</span> Delete
            </button>
        </div>
    </div>
    <div class="card-body">
        <div class="grid">
            <div>
                <p><strong>Name:</strong> <span id="vmName">-</span></p>
                <p><strong>VM Group:</strong> <span id="vmGroup">-</span></p>
                <p><strong>ID:</strong> <span id="vmId">%s</span></p>
                <p><strong>Status:</strong> <span id="vmStatus">-</span></p>
                <p><strong>PID:</strong> <span id="vmPid">-</span></p>
            </div>
            <div>
                <p><strong>vCPUs:</strong> <span id="vmVcpu">-</span></p>
                <p><strong>Memory:</strong> <span id="vmMemory">-</span> MB</p>
                <p><strong>IP Address:</strong> <a href="#" id="vmIpLink" onclick="openChangeIPModal(); return false;" title="Click to change IP address" style="color: var(--primary); text-decoration: none;"><span id="vmIp">-</span> <span class="material-icons" style="font-size: 14px; vertical-align: middle;">edit</span></a> <span id="vmReachable"></span></p>
                <p><strong>MAC Address:</strong> <span id="vmMac">-</span></p>
                <p><strong>DNS Servers:</strong> <span id="vmDns">-</span></p>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">storage</span>Disk Information</h3>
    </div>
    <div class="card-body">
        <div class="grid">
            <div>
                <p><strong>Operating System:</strong> <span id="vmOsRelease">-</span></p>
                <p><strong>Init System:</strong> <span id="vmInitSystem">-</span></p>
                <p><strong>Disk Type:</strong> <span id="vmDiskType">-</span></p>
            </div>
            <div>
                <p><strong>Root Disk Size:</strong> <span id="vmDiskSize">-</span>
                    <button class="btn btn-info btn-xs" id="expandRootFSBtn" onclick="triggerExpandRootFS()" title="Expand Root Filesystem" style="margin-left: 8px;">
                        <span class="material-icons">expand</span>
                    </button>
                </p>
                <p><strong>RootFS Path:</strong> <span id="vmRootfsPath" style="font-size: 12px; word-break: break-all;">-</span></p>
            </div>
        </div>
        <div id="attachedDisksSection" style="display: none; margin-top: 16px; border-top: 1px solid var(--border); padding-top: 16px;">
            <h4 style="margin-bottom: 12px;"><span class="material-icons" style="vertical-align: middle; margin-right: 8px; font-size: 18px;">disc_full</span>Attached Disks</h4>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Mount Point</th>
                        <th>Size</th>
                        <th>Format</th>
                    </tr>
                </thead>
                <tbody id="attachedDisksList">
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Historical Charts -->
<div class="card" id="chartsCard">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">show_chart</span>Performance History</h3>
        <div style="display: flex; gap: 8px;">
            <button class="btn btn-sm period-btn active" data-period="realtime" onclick="changePeriod('realtime')">Realtime</button>
            <button class="btn btn-sm period-btn" data-period="hour" onclick="changePeriod('hour')">Hour</button>
            <button class="btn btn-sm period-btn" data-period="day" onclick="changePeriod('day')">Day</button>
            <button class="btn btn-sm period-btn" data-period="week" onclick="changePeriod('week')">Week</button>
            <button class="btn btn-sm period-btn" data-period="month" onclick="changePeriod('month')">Month</button>
        </div>
    </div>
    <div class="card-body">
        <div id="chartsOffline" style="display: none; text-align: center; padding: 40px; color: var(--text-secondary);">
            <span class="material-icons" style="font-size: 48px; margin-bottom: 10px;">power_off</span>
            <p>VM is not running. Start the VM to see performance history.</p>
        </div>
        <div id="chartsOnline" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h4 style="font-size: 14px; color: var(--text-secondary); margin-bottom: 10px;">CPU Usage (%%)</h4>
                <div id="cpuChart" style="height: 250px;"></div>
            </div>
            <div>
                <h4 style="font-size: 14px; color: var(--text-secondary); margin-bottom: 10px;">Memory Usage (%%)</h4>
                <div id="memoryChart" style="height: 250px;"></div>
            </div>
        </div>
    </div>
</div>

<style>
.period-btn { background: #f5f5f5; color: #333; border: 1px solid #ddd; }
.period-btn:hover { background: #e0e0e0; }
.period-btn.active { background: var(--primary); color: white; border-color: var(--primary); }
</style>

<!-- Logs Modal -->
<div id="logsModal" class="modal">
    <div class="modal-content" style="width: 90%%; max-width: 1000px; height: 80vh;">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">article</span> VM Logs</h3>
            <span class="material-icons modal-close" onclick="closeModal('logsModal')">close</span>
        </div>
        <div class="modal-body" style="padding: 0; height: calc(100%% - 60px); display: flex; flex-direction: column;">
            <div style="padding: 15px; border-bottom: 1px solid var(--border-color); display: flex; gap: 10px; align-items: center;">
                <input type="text" id="logSearchInput" placeholder="Search logs..." style="flex: 1; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px;">
                <select id="logLevelFilter" style="padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px;">
                    <option value="">All Levels</option>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                </select>
                <button class="btn btn-secondary btn-sm" onclick="loadVMLogs()">
                    <span class="material-icons">refresh</span>
                </button>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 15px;">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 180px;">Time</th>
                            <th style="width: 80px;">Level</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody id="vmLogs">
                        <tr><td colspan="3">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
const vmId = '%s';

async function loadVMDetails() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/info');
    if (!ok) {
        alert('Failed to load VM details');
        return;
    }

    document.getElementById('vmName').textContent = data.name;
    document.getElementById('vmStatus').innerHTML = '<span class="badge badge-' +
        (data.status === 'running' ? 'success' : data.status === 'error' ? 'danger' : 'warning') +
        '">' + data.status + '</span>';
    document.getElementById('vmPid').textContent = data.pid || '-';
    document.getElementById('vmVcpu').textContent = data.vcpu;
    document.getElementById('vmMemory').textContent = data.memory_mb;
    document.getElementById('vmIp').textContent = data.ip_address || '-';
    document.getElementById('vmMac').textContent = data.mac_address || '-';
    document.getElementById('vmDns').textContent = data.dns_servers || '-';

    // Store network info for IP change feature
    window.currentVMNetworkId = data.network_id || '';
    window.currentVMIPAddress = data.ip_address || '';
    window.currentVMStatus = data.status;

    document.getElementById('startBtn').disabled = data.status === 'running';
    document.getElementById('stopBtn').disabled = data.status !== 'running';
    document.getElementById('consoleBtn').disabled = data.status !== 'running';
    document.getElementById('editBtn').disabled = data.status === 'running';

    // Check reachability if VM is running and has an IP
    const reachableSpan = document.getElementById('vmReachable');
    if (data.ip_address && data.status === 'running') {
        reachableSpan.innerHTML = '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite; font-size: 16px; vertical-align: middle;">sync</span>';
        checkReachability(data.ip_address);
    } else {
        reachableSpan.innerHTML = '';
    }

    // Populate disk information
    document.getElementById('vmOsRelease').textContent = data.os_release || '-';
    document.getElementById('vmInitSystem').textContent = data.init_system || '-';
    document.getElementById('vmDiskType').textContent = data.disk_type || '-';
    document.getElementById('vmDiskSize').textContent = data.disk_size_human || '-';
    document.getElementById('vmRootfsPath').textContent = data.rootfs_path || '-';

    // Load VM group info
    loadVMGroupInfo(vmId);

    // Populate attached disks if any
    const attachedDisksSection = document.getElementById('attachedDisksSection');
    const attachedDisksList = document.getElementById('attachedDisksList');
    if (data.attached_disks && data.attached_disks.length > 0) {
        attachedDisksSection.style.display = 'block';
        attachedDisksList.innerHTML = data.attached_disks.map(disk => `+"`"+`
            <tr>
                <td>${disk.name || '-'}</td>
                <td>${disk.mount_point || '-'}</td>
                <td>${disk.size_mb ? disk.size_mb + ' MB' : '-'}</td>
                <td>${disk.format || '-'}</td>
            </tr>
        `+"`"+`).join('');
    } else {
        attachedDisksSection.style.display = 'none';
        attachedDisksList.innerHTML = '';
    }

    // Store VM details for expand rootfs
    window.currentVMDetails = data;

    // Disable expand button if VM is running
    const expandBtn = document.getElementById('expandRootFSBtn');
    if (expandBtn) {
        expandBtn.disabled = data.status === 'running';
        expandBtn.title = data.status === 'running' ? 'Stop VM first to expand' : 'Expand Root Filesystem';
    }
}

async function loadVMGroupInfo(vmId) {
    const vmGroupSpan = document.getElementById('vmGroup');
    vmGroupSpan.textContent = 'Loading...';

    try {
        const { ok, data } = await apiCall('/api/vmgroups');
        if (!ok || !data.vm_groups) {
            vmGroupSpan.textContent = '-';
            return;
        }

        for (const group of data.vm_groups) {
            const vmsResp = await apiCall(`+"`"+`/api/vmgroups/${group.id}/vms`+"`"+`);
            if (vmsResp.ok && vmsResp.data.vms) {
                const vmInGroup = vmsResp.data.vms.find(v => v.id === vmId);
                if (vmInGroup) {
                    vmGroupSpan.innerHTML = `+"`"+`<a href="/vmgroups" style="color: var(--primary); text-decoration: none;">${group.name}</a>`+"`"+`;
                    return;
                }
            }
        }
        vmGroupSpan.textContent = 'None';
    } catch (e) {
        vmGroupSpan.textContent = '-';
    }
}

function triggerExpandRootFS() {
    if (window.currentVMDetails) {
        const sizeMB = window.currentVMDetails.disk_size_mb || 0;
        openExpandRootFSModal(vmId, window.currentVMDetails.name, sizeMB);
    }
}

async function checkReachability(ip) {
    const reachableSpan = document.getElementById('vmReachable');
    try {
        const { ok, data } = await apiCall('/api/ping/' + ip);
        if (ok) {
            if (data.reachable) {
                reachableSpan.innerHTML = '<span class="badge badge-success" style="margin-left: 8px;">Reachable</span>';
            } else {
                reachableSpan.innerHTML = '<span class="badge badge-danger" style="margin-left: 8px;">Unreachable</span>';
            }
        } else {
            reachableSpan.innerHTML = '<span class="badge badge-warning" style="margin-left: 8px;">Unknown</span>';
        }
    } catch (e) {
        reachableSpan.innerHTML = '<span class="badge badge-warning" style="margin-left: 8px;">Error</span>';
    }
}

let allLogs = [];

async function loadVMLogs() {
    const { ok, data } = await apiCall('/api/logs/' + vmId + '?limit=200');
    if (!ok) return;

    allLogs = data.logs || [];
    filterAndDisplayLogs();
}

function filterAndDisplayLogs() {
    const searchTerm = (document.getElementById('logSearchInput')?.value || '').toLowerCase();
    const levelFilter = document.getElementById('logLevelFilter')?.value || '';

    let filteredLogs = allLogs;

    if (levelFilter) {
        filteredLogs = filteredLogs.filter(log => log.level === levelFilter);
    }

    if (searchTerm) {
        filteredLogs = filteredLogs.filter(log =>
            log.message.toLowerCase().includes(searchTerm) ||
            log.level.toLowerCase().includes(searchTerm)
        );
    }

    const tbody = document.getElementById('vmLogs');
    if (filteredLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 40px; color: var(--text-secondary);">No logs found</td></tr>';
        return;
    }

    tbody.innerHTML = filteredLogs.map(log => `+"`"+`
        <tr>
            <td>${formatDate(log.created_at)}</td>
            <td><span class="badge badge-${log.level === 'error' ? 'danger' : log.level === 'warning' ? 'warning' : 'info'}">${log.level}</span></td>
            <td>${log.message}</td>
        </tr>
    `+"`"+`).join('');
}

function openLogsModal() {
    openModal('logsModal');
    loadVMLogs();
}

// Add event listeners for log filtering
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('logSearchInput');
    const levelFilter = document.getElementById('logLevelFilter');
    if (searchInput) {
        searchInput.addEventListener('input', filterAndDisplayLogs);
    }
    if (levelFilter) {
        levelFilter.addEventListener('change', filterAndDisplayLogs);
    }
});

async function loadVMMetrics() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/metrics');
    if (!ok) return;

    const offlineDiv = document.getElementById('vmStatsOffline');
    const onlineDiv = document.getElementById('vmStatsOnline');
    const chartsOffline = document.getElementById('chartsOffline');
    const chartsOnline = document.getElementById('chartsOnline');

    if (data.status !== 'running') {
        offlineDiv.style.display = 'block';
        onlineDiv.style.display = 'none';
        chartsOffline.style.display = 'block';
        chartsOnline.style.display = 'none';
        return;
    }

    offlineDiv.style.display = 'none';
    onlineDiv.style.display = 'block';
    chartsOffline.style.display = 'none';
    chartsOnline.style.display = 'grid';

    // Update CPU
    const cpuPercent = data.cpu_percent || 0;
    document.getElementById('statCpuPercent').textContent = cpuPercent.toFixed(1) + '%%';

    // Update Memory
    const memPercent = data.mem_percent || 0;
    const memUsed = data.mem_used_mb || 0;
    const memTotal = data.memory_mb || 0;
    document.getElementById('statMemPercent').textContent = memPercent.toFixed(1) + '%%';
    document.getElementById('statMemDetail').textContent = memUsed + ' / ' + memTotal + ' MB';

    // Update Uptime
    document.getElementById('statUptime').textContent = data.uptime || '-';

    // Update Config
    document.getElementById('statConfig').textContent = data.vcpu + ' / ' + data.memory_mb + 'MB';
}

// Charts
let cpuChart = null;
let memoryChart = null;
let currentPeriod = 'realtime';
let chartUpdateInterval = null;

function initCharts() {
    const chartOptions = {
        chart: {
            type: 'area',
            height: 250,
            animations: { enabled: true, easing: 'linear', dynamicAnimation: { speed: 1000 } },
            toolbar: { show: false },
            zoom: { enabled: false }
        },
        dataLabels: { enabled: false },
        stroke: { curve: 'smooth', width: 2 },
        fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.1, stops: [0, 90, 100] } },
        xaxis: { type: 'datetime', labels: { datetimeUTC: false, format: 'HH:mm:ss' } },
        yaxis: { min: 0, max: 100, labels: { formatter: (val) => val.toFixed(0) + '%%' } },
        tooltip: { x: { format: 'yyyy-MM-dd HH:mm:ss' }, y: { formatter: (val) => val.toFixed(1) + '%%' } },
        legend: { show: false }
    };

    cpuChart = new ApexCharts(document.getElementById('cpuChart'), {
        ...chartOptions,
        series: [{ name: 'CPU', data: [] }],
        colors: ['#1ab394']
    });
    cpuChart.render();

    memoryChart = new ApexCharts(document.getElementById('memoryChart'), {
        ...chartOptions,
        series: [{ name: 'Memory', data: [] }],
        colors: ['#1976d2']
    });
    memoryChart.render();
}

async function loadMetricsHistory(period) {
    // Ensure charts are initialized
    if (!cpuChart || !memoryChart) return;

    const { ok, data } = await apiCall('/api/vms/' + vmId + '/metrics-history?period=' + period);
    if (!ok) return;

    // Handle missing or null metrics array
    const metrics = data.metrics || [];

    const cpuData = metrics.map(m => ({ x: new Date(m.created_at).getTime(), y: m.cpu_percent }));
    const memData = metrics.map(m => ({ x: new Date(m.created_at).getTime(), y: m.mem_percent }));

    // Update x-axis format based on period
    let xFormat = 'HH:mm:ss';
    if (period === 'day') xFormat = 'HH:mm';
    else if (period === 'week') xFormat = 'MMM dd HH:mm';
    else if (period === 'month') xFormat = 'MMM dd';

    cpuChart.updateOptions({ xaxis: { labels: { format: xFormat } } });
    memoryChart.updateOptions({ xaxis: { labels: { format: xFormat } } });

    cpuChart.updateSeries([{ name: 'CPU', data: cpuData }]);
    memoryChart.updateSeries([{ name: 'Memory', data: memData }]);
}

function changePeriod(period) {
    currentPeriod = period;
    // Update button states
    document.querySelectorAll('.period-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.period === period) btn.classList.add('active');
    });
    loadMetricsHistory(period);

    // Set refresh interval based on period
    if (chartUpdateInterval) clearInterval(chartUpdateInterval);
    let interval = 10000; // 10 seconds for realtime
    if (period === 'hour') interval = 30000; // 30 seconds
    else if (period === 'day') interval = 60000; // 1 minute
    else if (period === 'week' || period === 'month') interval = 300000; // 5 minutes

    chartUpdateInterval = setInterval(() => loadMetricsHistory(period), interval);
}

// Initialize charts on page load
document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    changePeriod('realtime');
});

async function startVM() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/start', 'POST');
    if (ok) {
        loadVMDetails();
        loadVMMetrics();
    } else {
        alert(data.error || 'Failed to start VM');
    }
}

async function stopVM() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/stop', 'POST');
    if (ok) {
        loadVMDetails();
        loadVMMetrics();
    } else {
        alert(data.error || 'Failed to stop VM');
    }
}

async function deleteVM() {
    if (!confirm('Are you sure you want to delete this VM?')) return;
    const { ok, data } = await apiCall('/api/vms/' + vmId, 'DELETE');
    if (ok) {
        window.location.href = '/vms';
    } else {
        alert(data.error || 'Failed to delete VM');
    }
}

let vmData = null;

async function openEditModal() {
    // Fetch current VM data
    const { ok, data } = await apiCall('/api/vms/' + vmId);
    if (!ok) {
        alert(data.error || 'Failed to load VM');
        return;
    }
    vmData = data;

    // Populate form
    document.getElementById('editVmName').value = data.name;
    document.getElementById('editVmVcpu').value = data.vcpu;
    document.getElementById('editVmMemory').value = data.memory_mb;
    document.getElementById('editVmKernelArgs').value = data.kernel_args || '';
    document.getElementById('editVmDnsServers').value = data.dns_servers || '';

    // Load networks
    const networkSelect = document.getElementById('editVmNetwork');
    networkSelect.innerHTML = '<option value="">No network</option>';
    const networks = await apiCall('/api/networks');
    if (networks.ok && networks.data.networks) {
        networks.data.networks.forEach(n => {
            const selected = n.id === data.network_id ? 'selected' : '';
            networkSelect.innerHTML += `+"`"+`<option value="${n.id}" ${selected}>${n.name} (${n.subnet})</option>`+"`"+`;
        });
    }

    openModal('editVMModal');
}

async function saveVM() {
    const updateData = {
        name: document.getElementById('editVmName').value,
        vcpu: parseInt(document.getElementById('editVmVcpu').value) || 1,
        memory_mb: parseInt(document.getElementById('editVmMemory').value) || 512,
        network_id: document.getElementById('editVmNetwork').value,
        kernel_args: document.getElementById('editVmKernelArgs').value,
        dns_servers: document.getElementById('editVmDnsServers').value
    };

    const { ok, data } = await apiCall('/api/vms/' + vmId, 'PUT', updateData);
    if (ok) {
        closeModal('editVMModal');
        loadVMDetails();
    } else {
        alert(data.error || 'Failed to update VM');
    }
}

// Move to Group functionality
let currentMoveVmId = null;
let currentMoveVmGroupId = null;

async function openMoveToGroupModal(vmId, vmName) {
    currentMoveVmId = vmId;
    document.getElementById('moveToGroupVmId').value = vmId;
    document.getElementById('moveToGroupVmName').value = vmName;

    // Load available VM groups
    const { ok, data } = await apiCall('/api/vmgroups');
    const select = document.getElementById('moveToGroupSelect');
    select.innerHTML = '<option value="">-- No Group --</option>';

    if (ok && data.vm_groups) {
        data.vm_groups.forEach(g => {
            select.innerHTML += `+"`"+`<option value="${g.id}">${g.name}</option>`+"`"+`;
        });
    }

    // Check if VM is already in a group
    await checkVMCurrentGroup(vmId);

    openModal('moveToGroupModal');
}

async function openMoveToGroupModalDetail() {
    const vmId = document.getElementById('vmId').textContent;
    const vmName = document.getElementById('vmName').textContent;
    await openMoveToGroupModal(vmId, vmName);
}

async function checkVMCurrentGroup(vmId) {
    // Check all groups to find if VM is in one
    const { ok, data } = await apiCall('/api/vmgroups');
    const removeBtn = document.getElementById('removeFromGroupBtn');
    const currentGroupField = document.getElementById('moveToGroupCurrentGroup');

    currentMoveVmGroupId = null;
    currentGroupField.value = 'None';
    removeBtn.style.display = 'none';

    if (!ok || !data.vm_groups) return;

    for (const group of data.vm_groups) {
        const vmsResp = await apiCall(`+"`"+`/api/vmgroups/${group.id}/vms`+"`"+`);
        if (vmsResp.ok && vmsResp.data.vms) {
            const vmInGroup = vmsResp.data.vms.find(v => v.id === vmId);
            if (vmInGroup) {
                currentMoveVmGroupId = group.id;
                currentGroupField.value = group.name;
                removeBtn.style.display = 'inline-block';
                document.getElementById('moveToGroupSelect').value = group.id;
                break;
            }
        }
    }
}

async function submitMoveToGroup() {
    const vmId = document.getElementById('moveToGroupVmId').value;
    const newGroupId = document.getElementById('moveToGroupSelect').value;

    // If same group, just close
    if (newGroupId === currentMoveVmGroupId) {
        closeModal('moveToGroupModal');
        return;
    }

    // Remove from current group if exists
    if (currentMoveVmGroupId) {
        const { ok, data } = await apiCall(`+"`"+`/api/vmgroups/${currentMoveVmGroupId}/vms/${vmId}`+"`"+`, 'DELETE');
        if (!ok) {
            alert(data.error || 'Failed to remove VM from current group');
            return;
        }
    }

    // Add to new group if selected
    if (newGroupId) {
        const { ok, data } = await apiCall(`+"`"+`/api/vmgroups/${newGroupId}/vms`+"`"+`, 'POST', { vm_id: vmId });
        if (!ok) {
            alert(data.error || 'Failed to add VM to group');
            return;
        }
    }

    closeModal('moveToGroupModal');
    loadVMDetails();
    alert(newGroupId ? 'VM moved to group successfully' : 'VM removed from group successfully');
}

async function removeFromCurrentGroup() {
    const vmId = document.getElementById('moveToGroupVmId').value;

    if (!currentMoveVmGroupId) {
        alert('VM is not in any group');
        return;
    }

    const { ok, data } = await apiCall(`+"`"+`/api/vmgroups/${currentMoveVmGroupId}/vms/${vmId}`+"`"+`, 'DELETE');
    if (ok) {
        closeModal('moveToGroupModal');
        loadVMDetails();
        alert('VM removed from group successfully');
    } else {
        alert(data.error || 'Failed to remove VM from group');
    }
}

loadVMDetails();
loadVMMetrics();
setInterval(loadVMDetails, 5000);
setInterval(loadVMMetrics, 3000);
</script>

<!-- Move to VM Group Modal -->
<div id="moveToGroupModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Move to VM Group</h2>
            <span class="material-icons modal-close" onclick="closeModal('moveToGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="moveToGroupVmId">
            <div class="form-group">
                <label>VM</label>
                <input type="text" id="moveToGroupVmName" disabled>
            </div>
            <div class="form-group">
                <label>Current Group</label>
                <input type="text" id="moveToGroupCurrentGroup" disabled value="None">
            </div>
            <div class="form-group">
                <label>Select VM Group</label>
                <select id="moveToGroupSelect">
                    <option value="">-- Select a group --</option>
                </select>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('moveToGroupModal')">Cancel</button>
            <button type="button" class="btn btn-danger" onclick="removeFromCurrentGroup()" id="removeFromGroupBtn" style="display: none;">Remove from Group</button>
            <button type="button" class="btn btn-primary" onclick="submitMoveToGroup()">Move</button>
        </div>
    </div>
</div>

<div id="editVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Edit Virtual Machine</h3>
            <span class="material-icons modal-close" onclick="closeModal('editVMModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="editVMForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" id="editVmName" required>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" id="editVmVcpu" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" id="editVmMemory" min="128" step="128">
                </div>
                <div class="form-group">
                    <label>Network</label>
                    <select name="network_id" id="editVmNetwork">
                        <option value="">No network</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Kernel Arguments (optional)</label>
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0,115200n8 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" id="editVmDnsServers" placeholder="8.8.8.8,8.8.4.4">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
                </div>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 10px;">
                    Note: Kernel and RootFS cannot be changed after VM creation.
                </p>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('editVMModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveVM()">Save Changes</button>
        </div>
    </div>
</div>

<!-- Console Modal -->
<div id="consoleModal" class="modal">
    <div class="modal-content" style="width: 90%%; max-width: 1000px; height: 80vh;">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">terminal</span> VM Console</h3>
            <div style="display: flex; align-items: center; gap: 10px;">
                <button class="btn btn-secondary btn-sm" onclick="openConsoleInNewWindow()" title="Open in new window">
                    <span class="material-icons">open_in_new</span>
                </button>
                <span class="material-icons modal-close" onclick="closeConsole()">close</span>
            </div>
        </div>
        <div class="modal-body" style="padding: 0; height: calc(100%% - 60px);">
            <div id="terminal" style="width: 100%%; height: 100%%;"></div>
        </div>
    </div>
</div>

<!-- xterm.js -->
<link rel="stylesheet" href="/assets/xterm.css">
<script src="/assets/xterm.min.js"></script>
<script src="/assets/xterm-addon-fit.min.js"></script>

<script>
let term = null;
let ws = null;
let fitAddon = null;

function openConsole() {
    // Check if VM is running
    const startBtn = document.getElementById('startBtn');
    if (!startBtn.disabled) {
        alert('VM must be running to open console');
        return;
    }

    // Show modal
    openModal('consoleModal');

    // Initialize terminal if not already done
    if (!term) {
        term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            logLevel: 'off',
            cols: 80,
            rows: 24,
            convertEol: true,
            scrollback: 1000,
            theme: {
                background: '#1e1e1e',
                foreground: '#d4d4d4',
                cursor: '#d4d4d4',
                selection: '#264f78',
                black: '#000000',
                red: '#cd3131',
                green: '#0dbc79',
                yellow: '#e5e510',
                blue: '#2472c8',
                magenta: '#bc3fbc',
                cyan: '#11a8cd',
                white: '#e5e5e5'
            }
        });
        fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
    }

    // Open terminal in container
    const container = document.getElementById('terminal');
    container.innerHTML = '';
    term.open(container);

    // Fit terminal to container
    setTimeout(() => {
        fitAddon.fit();
    }, 100);

    // Connect WebSocket
    connectConsole();
}

function connectConsole() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = protocol + '//' + window.location.host + '/api/vms/console/' + vmId;

    ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';

    ws.onopen = function() {
        term.writeln('\r\n\x1b[32mConnected to VM console\x1b[0m\r\n');
    };

    ws.onmessage = function(event) {
        const data = new Uint8Array(event.data);
        term.write(data);
    };

    ws.onclose = function() {
        term.writeln('\r\n\x1b[31mConsole disconnected\x1b[0m\r\n');
    };

    ws.onerror = function(error) {
        term.writeln('\r\n\x1b[31mWebSocket error\x1b[0m\r\n');
    };

    // Send input to WebSocket
    term.onData(function(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    });
}

function closeConsole() {
    if (ws) {
        ws.close();
        ws = null;
    }
    closeModal('consoleModal');
}

function openConsoleInNewWindow() {
    closeConsole();
    window.open('/console/' + vmId, '_blank', 'width=1000,height=700');
}

// Handle window resize
window.addEventListener('resize', function() {
    if (fitAddon && document.getElementById('consoleModal').classList.contains('active')) {
        fitAddon.fit();
    }
});

// Change IP Address functions
async function openChangeIPModal() {
    if (!window.currentVMNetworkId) {
        alert('VM is not connected to a network. Cannot change IP address.');
        return;
    }

    // Show modal first
    document.getElementById('changeIPCurrentIP').textContent = window.currentVMIPAddress || '-';
    document.getElementById('changeIPSelect').innerHTML = '<option value="">Loading available IPs...</option>';
    document.getElementById('changeIPProgress').style.display = 'none';
    document.getElementById('changeIPBtn').disabled = false;

    // Show warning if VM is running
    const warningDiv = document.getElementById('changeIPRunningWarning');
    if (window.currentVMStatus === 'running') {
        warningDiv.style.display = 'block';
    } else {
        warningDiv.style.display = 'none';
    }

    openModal('changeIPModal');

    // Load available IPs
    const { ok, data } = await apiCall('/api/networks/' + window.currentVMNetworkId + '/available-ips');
    if (!ok) {
        document.getElementById('changeIPSelect').innerHTML = '<option value="">Error loading IPs</option>';
        return;
    }

    const select = document.getElementById('changeIPSelect');
    select.innerHTML = '<option value="">Select an IP address...</option>';

    if (data.available_ips && data.available_ips.length > 0) {
        data.available_ips.forEach(ip => {
            const isCurrent = ip === window.currentVMIPAddress;
            select.innerHTML += '<option value="' + ip + '"' + (isCurrent ? ' selected' : '') + '>' + ip + (isCurrent ? ' (current)' : '') + '</option>';
        });
    } else {
        select.innerHTML = '<option value="">No available IPs in network</option>';
    }
}

async function changeVMIP() {
    const newIP = document.getElementById('changeIPSelect').value;

    if (!newIP) {
        alert('Please select an IP address');
        return;
    }

    if (newIP === window.currentVMIPAddress) {
        closeModal('changeIPModal');
        return;
    }

    // Show progress
    document.getElementById('changeIPProgress').style.display = 'block';
    document.getElementById('changeIPBtn').disabled = true;
    document.getElementById('changeIPProgressText').textContent = 'Updating IP address...';

    const { ok, data } = await apiCall('/api/vms/' + vmId + '/change-ip', 'POST', { ip_address: newIP });

    if (ok) {
        if (data.restarted) {
            document.getElementById('changeIPProgressText').textContent = 'IP changed. VM restarting...';
            setTimeout(() => {
                closeModal('changeIPModal');
                loadVMDetails();
                loadVMMetrics();
            }, 2000);
        } else {
            closeModal('changeIPModal');
            loadVMDetails();
        }
    } else {
        document.getElementById('changeIPProgress').style.display = 'none';
        document.getElementById('changeIPBtn').disabled = false;
        alert(data.error || 'Failed to change IP address');
    }
}

// Expand RootFS functions
function openExpandRootFSModal(vmId, vmName, currentSizeMB) {
    document.getElementById('expandRootFSVmId').value = vmId;
    document.getElementById('expandRootFSVmName').textContent = vmName;
    document.getElementById('expandRootFSCurrentSize').textContent = currentSizeMB + ' MB';
    document.getElementById('expandRootFSNewSize').value = currentSizeMB + 512;
    document.getElementById('expandRootFSNewSize').min = currentSizeMB + 1;
    document.getElementById('expandRootFSProgress').style.display = 'none';
    document.getElementById('expandRootFSBtn').disabled = false;
    openModal('expandRootFSModal');
}

async function expandRootFS() {
    const vmIdToExpand = document.getElementById('expandRootFSVmId').value;
    const newSizeMB = parseInt(document.getElementById('expandRootFSNewSize').value);

    if (!newSizeMB || newSizeMB < 128) {
        alert('Please enter a valid size (minimum 128 MB)');
        return;
    }

    // Show progress
    document.getElementById('expandRootFSProgress').style.display = 'block';
    document.getElementById('expandRootFSBtn').disabled = true;
    document.getElementById('expandRootFSProgressText').textContent = 'Expanding disk...';

    // First get the VM info to find the rootfs ID
    const vmResp = await apiCall('/api/vms/' + vmIdToExpand);
    if (!vmResp.ok) {
        document.getElementById('expandRootFSProgress').style.display = 'none';
        document.getElementById('expandRootFSBtn').disabled = false;
        alert(vmResp.data.error || 'Failed to get VM info');
        return;
    }

    // Find the rootfs by path
    const rootfsPath = vmResp.data.rootfs_path;
    const rootfsResp = await apiCall('/api/rootfs');
    if (!rootfsResp.ok) {
        document.getElementById('expandRootFSProgress').style.display = 'none';
        document.getElementById('expandRootFSBtn').disabled = false;
        alert('Failed to find rootfs');
        return;
    }

    const rootfs = rootfsResp.data.rootfs.find(r => r.path === rootfsPath);
    if (!rootfs) {
        document.getElementById('expandRootFSProgress').style.display = 'none';
        document.getElementById('expandRootFSBtn').disabled = false;
        alert('RootFS not found in registry');
        return;
    }

    // Call the extend API
    const { ok, data } = await apiCall('/api/rootfs/extend/' + rootfs.id, 'POST', { new_size_mb: newSizeMB });

    document.getElementById('expandRootFSProgress').style.display = 'none';
    document.getElementById('expandRootFSBtn').disabled = false;

    if (ok) {
        closeModal('expandRootFSModal');
        alert('Disk expanded successfully to ' + newSizeMB + ' MB');
        loadVMDetails();
    } else {
        alert(data.error || 'Failed to expand disk');
    }
}
</script>

<!-- Expand RootFS Modal -->
<div id="expandRootFSModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">expand</span> Expand Root Filesystem</h3>
            <span class="material-icons modal-close" onclick="closeModal('expandRootFSModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="expandRootFSVmId">
            <div class="form-group">
                <label>Virtual Machine</label>
                <p id="expandRootFSVmName" style="font-size: 16px; font-weight: 500;">-</p>
            </div>
            <div class="form-group">
                <label>Current Size</label>
                <p id="expandRootFSCurrentSize" style="font-size: 16px; font-weight: 500; color: var(--primary);">-</p>
            </div>
            <div class="form-group">
                <label>New Size (MB)</label>
                <input type="number" id="expandRootFSNewSize" required min="128" max="102400" step="128">
                <small style="color: var(--text-secondary); font-size: 11px;">Must be larger than current size. Maximum 100 GB.</small>
            </div>
            <div id="expandRootFSProgress" style="display: none; margin-top: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>
                    <span id="expandRootFSProgressText">Expanding disk...</span>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('expandRootFSModal')">Cancel</button>
            <button type="button" class="btn btn-primary" id="expandRootFSBtn" onclick="expandRootFS()"><span class="material-icons">expand</span> Expand</button>
        </div>
    </div>
</div>

<!-- Change IP Address Modal -->
<div id="changeIPModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">lan</span> Change IP Address</h3>
            <span class="material-icons modal-close" onclick="closeModal('changeIPModal')">close</span>
        </div>
        <div class="modal-body">
            <div id="changeIPRunningWarning" style="display: none; background: #fff3e0; border: 1px solid #ffb74d; border-radius: 6px; padding: 12px; margin-bottom: 15px;">
                <span class="material-icons" style="color: #f57c00; vertical-align: middle;">warning</span>
                <strong style="color: #e65100;">VM is currently running.</strong>
                <p style="margin: 5px 0 0; color: #795548; font-size: 13px;">The VM will be automatically restarted after the IP change to apply the new configuration.</p>
            </div>
            <div class="form-group">
                <label>Current IP Address</label>
                <p id="changeIPCurrentIP" style="font-size: 16px; font-weight: 500; color: var(--primary);">-</p>
            </div>
            <div class="form-group">
                <label>New IP Address</label>
                <select id="changeIPSelect" style="width: 100%%;">
                    <option value="">Loading available IPs...</option>
                </select>
                <small style="color: var(--text-secondary); font-size: 11px;">Only free IP addresses in the network are shown.</small>
            </div>
            <div id="changeIPProgress" style="display: none; margin-top: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>
                    <span id="changeIPProgressText">Updating IP address...</span>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('changeIPModal')">Cancel</button>
            <button type="button" class="btn btn-primary" id="changeIPBtn" onclick="changeVMIP()"><span class="material-icons">save</span> Save</button>
        </div>
    </div>
</div>
`, vmID, vmID)
}

func (wc *WebConsole) renderNetworksPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Networks</h3>
        <button class="btn btn-primary" onclick="openModal('createNetworkModal')">
            <span class="material-icons">add</span>
            Create Network
        </button>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Bridge</th>
                    <th>Subnet</th>
                    <th>Gateway</th>
                    <th>Status</th>
                    <th>NAT</th>
                    <th>Firewall</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="networkList">
                <tr><td colspan="8">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="createNetworkModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Network</h3>
            <span class="material-icons modal-close" onclick="closeModal('createNetworkModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createNetworkForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" required placeholder="my-network">
                </div>
                <div class="form-group">
                    <label>Subnet (CIDR)</label>
                    <input type="text" name="subnet" required placeholder="192.168.100.0/24">
                </div>
                <div class="form-group">
                    <label>Gateway (optional)</label>
                    <input type="text" name="gateway" placeholder="192.168.100.1">
                </div>
                <div class="form-group">
                    <label>External Interface (for NAT)</label>
                    <select name="out_interface" id="outInterfaceSelect">
                        <option value="">Auto-detect</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>MTU</label>
                    <input type="number" name="mtu" value="1500" min="576" max="65535">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="enable_nat" checked style="width: auto; margin-right: 8px;"> Enable NAT
                        </label>
                    </div>
                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="stp" style="width: auto; margin-right: 8px;"> Enable STP
                        </label>
                    </div>
                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="block_external" style="width: auto; margin-right: 8px;"> Block External Access
                        </label>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createNetworkModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createNetwork()">Create</button>
        </div>
    </div>
</div>

<div id="networkDetailsModal" class="modal">
    <div class="modal-content modal-lg">
        <div class="modal-header">
            <h3>Network Details</h3>
            <span class="material-icons modal-close" onclick="closeModal('networkDetailsModal')">close</span>
        </div>
        <div class="modal-body">
            <div class="tabs">
                <button class="tab-btn active" onclick="showNetworkTab('general')">General</button>
                <button class="tab-btn" onclick="showNetworkTab('firewall')">Firewall</button>
                <button class="tab-btn" onclick="showNetworkTab('vms')">VMs</button>
            </div>
            <div id="networkGeneralTab" class="tab-content active">
                <div class="network-info">
                    <div class="info-row"><label>Name:</label><span id="netDetailName"></span></div>
                    <div class="info-row"><label>Bridge:</label><span id="netDetailBridge"></span></div>
                    <div class="info-row"><label>Subnet:</label><span id="netDetailSubnet"></span></div>
                    <div class="info-row"><label>Gateway:</label><span id="netDetailGateway"></span></div>
                    <div class="info-row"><label>Status:</label><span id="netDetailStatus"></span></div>
                    <div class="info-row"><label>NAT:</label><span id="netDetailNAT"></span></div>
                    <div class="info-row"><label>External Interface:</label><span id="netDetailOutIface"></span></div>
                </div>
                <h4>Bridge Settings</h4>
                <form id="bridgeSettingsForm">
                    <input type="hidden" id="editNetworkId" name="network_id">
                    <div class="form-row">
                        <div class="form-group">
                            <label>MTU</label>
                            <input type="number" name="mtu" id="bridgeMTU" min="576" max="65535">
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center; cursor: pointer;">
                                <input type="checkbox" name="stp" id="bridgeSTP" style="width: auto; margin-right: 8px;"> Enable STP
                            </label>
                        </div>
                    </div>
                    <button type="button" class="btn btn-primary" onclick="saveBridgeSettings()">Save Bridge Settings</button>
                </form>
            </div>
            <div id="networkFirewallTab" class="tab-content">
                <div class="form-group">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="blockExternalCheck" onchange="toggleBlockExternal()" style="width: auto; margin-right: 8px;">
                        Block all external access (recommended)
                    </label>
                </div>
                <h4>Firewall Rules</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Details</th>
                            <th>Protocol</th>
                            <th>Enabled</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="firewallRulesList">
                        <tr><td colspan="5">Loading...</td></tr>
                    </tbody>
                </table>
                <button class="btn btn-primary" onclick="openModal('addFirewallRuleModal')">
                    <span class="material-icons">add</span>
                    Add Rule
                </button>
            </div>
            <div id="networkVMsTab" class="tab-content">
                <table>
                    <thead>
                        <tr>
                            <th>VM Name</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="networkVMsList">
                        <tr><td colspan="4">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('networkDetailsModal')">Close</button>
        </div>
    </div>
</div>

<div id="addFirewallRuleModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Add Firewall Rule</h3>
            <span class="material-icons modal-close" onclick="closeModal('addFirewallRuleModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="addFirewallRuleForm">
                <div class="form-group">
                    <label>Rule Type</label>
                    <select name="rule_type" id="ruleTypeSelect" onchange="updateRuleTypeFields()">
                        <option value="source_ip">Allow Source IP/CIDR</option>
                        <option value="port_forward">Port Forward</option>
                        <option value="port_allow">Allow Port</option>
                    </select>
                </div>
                <div id="sourceIPFields" class="rule-fields">
                    <div class="form-group">
                        <label>Source IP/CIDR</label>
                        <input type="text" name="source_ip" placeholder="192.168.1.0/24">
                    </div>
                </div>
                <div id="portForwardFields" class="rule-fields" style="display:none">
                    <div class="form-group">
                        <label>Host Port (External)</label>
                        <input type="number" name="host_port" placeholder="8080">
                    </div>
                    <div class="form-group">
                        <label>Destination VM IP</label>
                        <select name="dest_ip" id="destVMSelect">
                            <option value="">Select VM</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Destination Port</label>
                        <input type="number" name="dest_port_fwd" placeholder="80">
                    </div>
                </div>
                <div id="portAllowFields" class="rule-fields" style="display:none">
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" name="dest_port_allow" placeholder="22">
                    </div>
                </div>
                <div class="form-group">
                    <label>Protocol</label>
                    <select name="protocol">
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="all">Both</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Description (optional)</label>
                    <input type="text" name="description" placeholder="SSH access from office">
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('addFirewallRuleModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="addFirewallRule()">Add Rule</button>
        </div>
    </div>
</div>

<style>
.tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
.tab-btn { background: none; border: none; padding: 8px 16px; cursor: pointer; border-radius: 4px; }
.tab-btn.active { background: var(--primary); color: white; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.network-info { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
.info-row { display: flex; gap: 10px; }
.info-row label { font-weight: bold; min-width: 120px; }
.form-row { display: flex; gap: 20px; flex-wrap: wrap; }
.form-row .form-group { flex: 1; min-width: 150px; }
.rule-fields { margin-top: 10px; }
.modal-lg { max-width: 800px; }
</style>

<script>
let currentNetworkId = null;
let networkVMs = [];

async function loadNetworks() {
    const { ok, data } = await apiCall('/api/networks');
    if (!ok) return;

    const tbody = document.getElementById('networkList');
    if (!data.networks || data.networks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state"><span class="material-icons">hub</span><p>No networks</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.networks.map(net => ` + "`" + `
        <tr>
            <td>${net.name}</td>
            <td>${net.bridge_name}</td>
            <td>${net.subnet}</td>
            <td>${net.gateway}</td>
            <td>
                <span class="badge badge-${net.status === 'active' ? 'success' : 'warning'}">
                    ${net.status}
                </span>
            </td>
            <td>${net.enable_nat ? 'Yes' : 'No'}</td>
            <td>
                <span class="badge badge-${net.block_external ? 'info' : 'secondary'}">
                    ${net.block_external ? 'Protected' : 'Open'}
                </span>
            </td>
            <td class="actions">
                <button class="btn btn-info btn-sm" onclick="openNetworkDetails('${net.id}')" title="Manage">
                    <span class="material-icons">settings</span>
                </button>
                ${net.status === 'inactive'
                    ? ` + "`" + `<button class="btn btn-success btn-sm" onclick="activateNetwork('${net.id}')" title="Activate"><span class="material-icons">power</span></button>` + "`" + `
                    : ` + "`" + `<button class="btn btn-warning btn-sm" onclick="deactivateNetwork('${net.id}')" title="Deactivate"><span class="material-icons">power_off</span></button>` + "`" + `
                }
                <button class="btn btn-secondary btn-sm" onclick="deleteNetwork('${net.id}')" ${net.status === 'active' ? 'disabled' : ''} title="Delete">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function loadInterfaces() {
    const { ok, data } = await apiCall('/api/interfaces');
    if (!ok) return;
    const select = document.getElementById('outInterfaceSelect');
    if (select && data.interfaces) {
        data.interfaces.forEach(iface => {
            const opt = document.createElement('option');
            opt.value = iface;
            opt.textContent = iface;
            select.appendChild(opt);
        });
    }
}

async function createNetwork() {
    const form = document.getElementById('createNetworkForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        subnet: formData.get('subnet'),
        gateway: formData.get('gateway') || '',
        out_interface: formData.get('out_interface') || '',
        mtu: parseInt(formData.get('mtu')) || 1500,
        enable_nat: formData.get('enable_nat') === 'on',
        stp: formData.get('stp') === 'on',
        block_external: formData.get('block_external') === 'on'
    };

    const { ok, data: resp } = await apiCall('/api/networks', 'POST', data);
    if (ok) {
        closeModal('createNetworkModal');
        form.reset();
        loadNetworks();
    } else {
        alert(resp.error || 'Failed to create network');
    }
}

async function openNetworkDetails(id) {
    currentNetworkId = id;
    const { ok, data: net } = await apiCall('/api/networks/' + id);
    if (!ok) return;

    document.getElementById('editNetworkId').value = id;
    document.getElementById('netDetailName').textContent = net.name;
    document.getElementById('netDetailBridge').textContent = net.bridge_name;
    document.getElementById('netDetailSubnet').textContent = net.subnet;
    document.getElementById('netDetailGateway').textContent = net.gateway;
    document.getElementById('netDetailStatus').innerHTML = '<span class="badge badge-' + (net.status === 'active' ? 'success' : 'warning') + '">' + net.status + '</span>';
    document.getElementById('netDetailNAT').textContent = net.enable_nat ? 'Yes' : 'No';
    document.getElementById('netDetailOutIface').textContent = net.out_interface || 'Auto';
    document.getElementById('bridgeMTU').value = net.mtu || 1500;
    document.getElementById('bridgeSTP').checked = net.stp;
    document.getElementById('blockExternalCheck').checked = net.block_external;

    // Load VMs
    loadNetworkVMs(id);
    // Load firewall rules
    loadFirewallRules(id);

    showNetworkTab('general');
    openModal('networkDetailsModal');
}

async function loadNetworkVMs(id) {
    const { ok, data } = await apiCall('/api/networks/' + id + '/vms');
    const tbody = document.getElementById('networkVMsList');
    if (!ok || !data.vms || data.vms.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No VMs attached</td></tr>';
        networkVMs = [];
        return;
    }
    networkVMs = data.vms;
    tbody.innerHTML = data.vms.map(vm => ` + "`" + `
        <tr>
            <td>${vm.name}</td>
            <td>${vm.ip_address}</td>
            <td>${vm.mac_address}</td>
            <td><span class="badge badge-${vm.status === 'running' ? 'success' : 'secondary'}">${vm.status}</span></td>
        </tr>
    ` + "`" + `).join('');
    // Update dest VM select
    updateDestVMSelect();
}

function updateDestVMSelect() {
    const select = document.getElementById('destVMSelect');
    select.innerHTML = '<option value="">Select VM</option>';
    networkVMs.forEach(vm => {
        if (vm.ip_address) {
            const opt = document.createElement('option');
            opt.value = vm.ip_address;
            opt.textContent = vm.name + ' (' + vm.ip_address + ')';
            select.appendChild(opt);
        }
    });
}

async function loadFirewallRules(id) {
    const { ok, data } = await apiCall('/api/networks/' + id + '/firewall');
    const tbody = document.getElementById('firewallRulesList');
    if (!ok) return;

    document.getElementById('blockExternalCheck').checked = data.block_external;

    if (!data.rules || data.rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No firewall rules</td></tr>';
        return;
    }

    tbody.innerHTML = data.rules.map(rule => {
        let details = '';
        switch(rule.rule_type) {
            case 'source_ip':
                details = 'Allow from ' + rule.source_ip;
                break;
            case 'port_forward':
                details = ':' + rule.host_port + ' → ' + rule.dest_ip + ':' + rule.dest_port;
                break;
            case 'port_allow':
                details = 'Allow port ' + rule.dest_port;
                break;
        }
        return ` + "`" + `
        <tr>
            <td>${rule.rule_type}</td>
            <td>${details}</td>
            <td>${rule.protocol.toUpperCase()}</td>
            <td>
                <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleFirewallRule('${rule.id}', this.checked)">
            </td>
            <td>
                <button class="btn btn-danger btn-sm" onclick="deleteFirewallRule('${rule.id}')">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `}).join('');
}

async function toggleBlockExternal() {
    const checked = document.getElementById('blockExternalCheck').checked;
    await apiCall('/api/networks/' + currentNetworkId + '/firewall', 'PUT', { block_external: checked });
}

async function toggleFirewallRule(ruleId, enabled) {
    await apiCall('/api/networks/' + currentNetworkId + '/firewall/' + ruleId, 'PUT', { enabled: enabled });
}

async function deleteFirewallRule(ruleId) {
    if (!confirm('Delete this firewall rule?')) return;
    const { ok } = await apiCall('/api/networks/' + currentNetworkId + '/firewall/' + ruleId, 'DELETE');
    if (ok) loadFirewallRules(currentNetworkId);
}

function updateRuleTypeFields() {
    const type = document.getElementById('ruleTypeSelect').value;
    document.getElementById('sourceIPFields').style.display = type === 'source_ip' ? 'block' : 'none';
    document.getElementById('portForwardFields').style.display = type === 'port_forward' ? 'block' : 'none';
    document.getElementById('portAllowFields').style.display = type === 'port_allow' ? 'block' : 'none';
}

async function addFirewallRule() {
    const form = document.getElementById('addFirewallRuleForm');
    const formData = new FormData(form);
    const ruleType = formData.get('rule_type');

    const data = {
        rule_type: ruleType,
        protocol: formData.get('protocol'),
        description: formData.get('description')
    };

    switch(ruleType) {
        case 'source_ip':
            data.source_ip = formData.get('source_ip');
            break;
        case 'port_forward':
            data.host_port = parseInt(formData.get('host_port'));
            data.dest_ip = formData.get('dest_ip');
            data.dest_port = parseInt(formData.get('dest_port_fwd'));
            break;
        case 'port_allow':
            data.dest_port = parseInt(formData.get('dest_port_allow'));
            break;
    }

    const { ok, data: resp } = await apiCall('/api/networks/' + currentNetworkId + '/firewall', 'POST', data);
    if (ok) {
        closeModal('addFirewallRuleModal');
        form.reset();
        loadFirewallRules(currentNetworkId);
    } else {
        alert(resp.error || 'Failed to add rule');
    }
}

async function saveBridgeSettings() {
    const mtu = parseInt(document.getElementById('bridgeMTU').value);
    const stp = document.getElementById('bridgeSTP').checked;
    const { ok, data } = await apiCall('/api/networks/' + currentNetworkId + '/bridge', 'PUT', { mtu, stp });
    if (ok) {
        alert('Bridge settings saved');
    } else {
        alert(data.error || 'Failed to save settings');
    }
}

function showNetworkTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.querySelector('.tab-btn[onclick*="' + tab + '"]').classList.add('active');
    document.getElementById('network' + tab.charAt(0).toUpperCase() + tab.slice(1) + 'Tab').classList.add('active');
}

async function activateNetwork(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/networks/${id}/activate` + "`" + `, 'POST');
    if (ok) {
        loadNetworks();
    } else {
        alert(data.error || 'Failed to activate network');
    }
}

async function deactivateNetwork(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/networks/${id}/deactivate` + "`" + `, 'POST');
    if (ok) {
        loadNetworks();
    } else {
        alert(data.error || 'Failed to deactivate network');
    }
}

async function deleteNetwork(id) {
    if (!confirm('Are you sure you want to delete this network?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/networks/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadNetworks();
    } else {
        alert(data.error || 'Failed to delete network');
    }
}

loadNetworks();
loadInterfaces();
</script>
`
}

func (wc *WebConsole) renderImagesPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Kernel Images</h3>
        <button class="btn btn-primary" onclick="openModal('downloadKernelModal')">
            <span class="material-icons">download</span>
            Download Kernel
        </button>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Version</th>
                    <th>Architecture</th>
                    <th>Size</th>
                    <th>Default</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="kernelList">
                <tr><td colspan="6">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Root Filesystems</h3>
        <div class="actions">
            <button class="btn btn-primary" onclick="openModal('downloadRootfsModal')">
                <span class="material-icons">download</span>
                Download
            </button>
            <button class="btn btn-secondary" onclick="openModal('uploadRootfsModal')">
                <span class="material-icons">upload</span>
                Upload
            </button>
            <button class="btn btn-secondary" onclick="openModal('createDebianModal')">
                <span class="material-icons">build</span>
                Create Image
            </button>
        </div>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Format</th>
                    <th>Size</th>
                    <th>OS / Init</th>
                    <th>Used By</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="rootfsList">
                <tr><td colspan="7">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="downloadKernelModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Download Kernel</h3>
            <span class="material-icons modal-close" onclick="closeModal('downloadKernelModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="downloadKernelForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" value="vmlinux" required>
                </div>
                <div class="form-group">
                    <label>Version</label>
                    <input type="text" name="version" value="5.10">
                </div>
                <div class="form-group">
                    <label>Download URL (leave empty for default)</label>
                    <input type="url" name="url" placeholder="https://...">
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('downloadKernelModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="downloadKernel()">Download</button>
        </div>
    </div>
</div>

<div id="downloadRootfsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Download Root Filesystem</h3>
            <span class="material-icons modal-close" onclick="closeModal('downloadRootfsModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="downloadRootfsForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" value="ubuntu-22.04.ext4" required>
                </div>
                <div class="form-group">
                    <label>Download URL (leave empty for default)</label>
                    <input type="url" name="url" placeholder="https://...">
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('downloadRootfsModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="downloadRootfs()">Download</button>
        </div>
    </div>
</div>

<div id="uploadRootfsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Upload Root Filesystem</h3>
            <span class="material-icons modal-close" onclick="closeModal('uploadRootfsModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="uploadRootfsForm" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" id="uploadRootfsName" required placeholder="my-rootfs.ext4">
                </div>
                <div class="form-group">
                    <label>Root Filesystem File</label>
                    <input type="file" name="file" id="uploadRootfsFile" required accept=".ext4,.img,.raw,.qcow2">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Supported formats: ext4, img, raw. Large files are supported.</small>
                </div>
                <div id="uploadProgress" style="display: none; margin-top: 15px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span id="uploadProgressText">Uploading...</span>
                        <span id="uploadProgressPercent">0%%</span>
                    </div>
                    <div style="background: var(--border); border-radius: 4px; height: 8px; overflow: hidden;">
                        <div id="uploadProgressBar" style="background: var(--primary); height: 100%%; width: 0%%; transition: width 0.3s;"></div>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('uploadRootfsModal')" id="uploadCancelBtn">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="uploadRootfs()" id="uploadSubmitBtn">Upload</button>
        </div>
    </div>
</div>

<div id="duplicateRootfsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Duplicate Root Filesystem</h3>
            <span class="material-icons modal-close" onclick="closeModal('duplicateRootfsModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="duplicateRootfsForm">
                <input type="hidden" id="duplicateRootfsId">
                <p style="margin-bottom: 15px; color: var(--text-secondary);">Creating a copy of: <strong id="duplicateRootfsSource"></strong></p>
                <div class="form-group">
                    <label>New Name</label>
                    <input type="text" id="duplicateRootfsName" required placeholder="my-rootfs-copy.ext4">
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('duplicateRootfsModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="duplicateRootfs()">Duplicate</button>
        </div>
    </div>
</div>

<div id="renameRootfsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Rename Root Filesystem</h3>
            <span class="material-icons modal-close" onclick="closeModal('renameRootfsModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="renameRootfsForm">
                <input type="hidden" id="renameRootfsId">
                <div class="form-group">
                    <label>New Name</label>
                    <input type="text" id="renameRootfsName" required placeholder="my-rootfs.ext4">
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('renameRootfsModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="renameRootfs()">Rename</button>
        </div>
    </div>
</div>

<div id="extendDiskModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Extend Disk Size</h3>
            <span class="material-icons modal-close" onclick="closeModal('extendDiskModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="extendDiskForm">
                <input type="hidden" id="extendDiskId">
                <div class="form-group">
                    <label>Root Filesystem</label>
                    <input type="text" id="extendDiskName" readonly style="background: var(--bg-tertiary);">
                </div>
                <div class="form-group">
                    <label>Current Size</label>
                    <input type="text" id="extendDiskCurrentSize" readonly style="background: var(--bg-tertiary);">
                </div>
                <div class="form-group">
                    <label>New Size (MB)</label>
                    <input type="number" id="extendDiskNewSize" required min="128" max="102400" step="128">
                    <small style="color: var(--text-secondary); font-size: 11px;">Minimum 128 MB, maximum 100 GB. Must be larger than current size.</small>
                </div>
            </form>
            <div id="extendDiskProgress" style="display: none; margin-top: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>
                    <span id="extendDiskProgressText">Extending disk...</span>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('extendDiskModal')">Cancel</button>
            <button type="button" class="btn btn-primary" id="extendDiskBtn" onclick="extendDisk()"><span class="material-icons">expand</span> Extend</button>
        </div>
    </div>
</div>

<div id="createVMFromRootfsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Virtual Machine</h3>
            <span class="material-icons modal-close" onclick="closeModal('createVMFromRootfsModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createVMFromRootfsForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" id="vmFromRootfsName" required>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" value="1" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" value="512" min="128" step="128">
                </div>
                <div class="form-group">
                    <label>Kernel</label>
                    <select name="kernel_id" required id="vmFromRootfsKernelSelect">
                        <option value="">Select kernel...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Root Filesystem</label>
                    <select name="rootfs_id" required id="vmFromRootfsSelect">
                        <option value="">Select rootfs...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Network</label>
                    <select name="network_id" id="vmFromRootfsNetworkSelect">
                        <option value="">No network</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Data Disk (optional)</label>
                    <select name="data_disk_id" id="vmFromRootfsDataDiskSelect">
                        <option value="">No data disk</option>
                    </select>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Attach an additional data disk to the VM.</small>
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" placeholder="8.8.8.8,8.8.4.4">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs.</small>
                </div>
                <div class="form-group">
                    <label>Root Password (optional)</label>
                    <input type="password" name="root_password" id="vmFromRootfsPassword" placeholder="Leave empty to keep existing">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Set root password for the VM. Will be applied on first start.</small>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createVMFromRootfsModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createVMFromRootfs()">Create VM</button>
        </div>
    </div>
</div>

<div id="createDebianModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Debian Image</h3>
            <span class="material-icons modal-close" onclick="closeModal('createDebianModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createDebianForm">
                <div class="form-group">
                    <label>Debian Version</label>
                    <select id="debianVersion" required>
                        <option value="bookworm">Bookworm (Debian 12 - Stable)</option>
                        <option value="trixie">Trixie (Debian 13 - Testing)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Image Name</label>
                    <input type="text" id="debianImageName" required placeholder="debian-bookworm" pattern="[a-zA-Z0-9_-]+">
                    <small style="color: var(--text-secondary);">Only letters, numbers, dashes and underscores allowed</small>
                </div>
                <div class="form-group">
                    <label>Disk Size (MB)</label>
                    <input type="number" id="debianDiskSize" required value="1024" min="512" max="20480" step="128">
                    <small style="color: var(--text-secondary);">Minimum 512 MB, maximum 20 GB</small>
                </div>
                <div class="form-group">
                    <label>Builder Directory</label>
                    <input type="text" id="debianBuilderDir" value="/home/Builder" placeholder="/home/Builder">
                    <small style="color: var(--text-secondary);">Temporary working directory for build process</small>
                </div>
            </form>
            <div id="debianBuildProgress" style="display: none; margin-top: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span id="debianBuildStep" style="font-weight: 500;">Initializing...</span>
                    <span id="debianBuildPercent">0%%</span>
                </div>
                <div style="background: var(--border); border-radius: 4px; height: 12px; overflow: hidden;">
                    <div id="debianBuildBar" style="background: var(--primary); height: 100%%; width: 0%%; transition: width 0.5s;"></div>
                </div>
                <p id="debianBuildMessage" style="margin-top: 8px; color: var(--text-secondary); font-size: 13px;"></p>
            </div>
            <div id="debianBuildResult" style="display: none; margin-top: 20px;"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeDebianBuildModal()" id="debianCancelBtn">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="startDebianBuild()" id="debianBuildBtn">
                <span class="material-icons">build</span> Build Image
            </button>
        </div>
    </div>
</div>

<script>
async function loadKernels() {
    const { ok, data } = await apiCall('/api/kernels');
    if (!ok) return;

    const tbody = document.getElementById('kernelList');
    if (!data.kernels || data.kernels.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><span class="material-icons">storage</span><p>No kernels</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.kernels.map(k => ` + "`" + `
        <tr>
            <td>${k.name}</td>
            <td>${k.version}</td>
            <td>${k.architecture}</td>
            <td>${formatBytes(k.size)}</td>
            <td>${k.is_default ? '<span class="badge badge-success">Default</span>' : ''}</td>
            <td class="actions">
                ${!k.is_default ? ` + "`" + `<button class="btn btn-secondary btn-sm" onclick="setDefaultKernel('${k.id}')">Set Default</button>` + "`" + ` : ''}
                <button class="btn btn-danger btn-sm" onclick="deleteKernel('${k.id}')">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function loadRootfs() {
    const { ok, data } = await apiCall('/api/rootfs');
    if (!ok) return;

    const tbody = document.getElementById('rootfsList');
    if (!data.rootfs || data.rootfs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><span class="material-icons">storage</span><p>No root filesystems</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.rootfs.map(r => {
        // Disk type badge
        let typeBadge = '';
        if (r.disk_type === 'system') {
            typeBadge = '<span class="badge badge-success">System</span>';
        } else if (r.disk_type === 'data') {
            typeBadge = '<span class="badge badge-info">Data</span>';
        } else if (r.disk_type === 'unknown') {
            typeBadge = '<span class="badge badge-warning">Unknown</span>';
        } else {
            typeBadge = '<span class="badge badge-secondary">Scanning...</span>';
        }

        // OS/Init info
        let osInfo = '';
        if (r.os_release) {
            osInfo = r.os_release;
        } else if (r.init_system) {
            osInfo = r.init_system;
        } else if (r.disk_type === 'data') {
            osInfo = '-';
        } else {
            osInfo = '<span style="color: var(--text-secondary)">-</span>';
        }

        // Used by VMs
        let usedByHtml = '';
        if (r.used_by_vms && r.used_by_vms.length > 0) {
            usedByHtml = r.used_by_vms.map(vm => {
                const statusClass = vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'secondary';
                return '<a href="/vms/' + vm.id + '" class="badge badge-' + statusClass + '" style="text-decoration: none; margin-right: 4px;" title="' + vm.status + '">' + vm.name + '</a>';
            }).join('');
        } else {
            usedByHtml = '<span style="color: var(--text-secondary)">-</span>';
        }

        // Check if rootfs is in use
        const inUse = r.used_by_vms && r.used_by_vms.length > 0;

        return ` + "`" + `
        <tr>
            <td>${r.name}</td>
            <td>${typeBadge}</td>
            <td>${r.format}</td>
            <td>${formatBytes(r.size)}</td>
            <td>${osInfo}</td>
            <td style="white-space: nowrap;">${usedByHtml}</td>
            <td class="actions">
                <div class="dropdown">
                    <button class="btn btn-secondary btn-xs dropdown-toggle" onclick="toggleDropdown(this)">
                        <span class="material-icons">more_vert</span>
                    </button>
                    <div class="dropdown-menu">
                        ${r.disk_type === 'system' ? '<a href="#" onclick="openCreateVMFromRootfs(\'' + r.id + '\', \'' + r.name + '\'); return false;"><span class="material-icons">add_box</span> Create VM</a>' : ''}
                        <a href="#" onclick="openDuplicateRootfsModal('${r.id}', '${r.name}'); return false;"><span class="material-icons">content_copy</span> Duplicate</a>
                        <a href="#" onclick="openRenameRootfsModal('${r.id}', '${r.name}'); return false;"><span class="material-icons">edit</span> Rename</a>
                        <a href="#" onclick="openExtendDiskModal('${r.id}', '${r.name}', ${r.size}); return false;"><span class="material-icons">expand</span> Extend Disk</a>
                        <div class="dropdown-divider"></div>
                        <a href="#" class="danger ${inUse ? 'disabled' : ''}" onclick="${inUse ? 'alert(\'Cannot delete: rootfs is in use by VMs\'); return false;' : 'deleteRootfs(\'' + r.id + '\'); return false;'}"><span class="material-icons">delete</span> Delete</a>
                    </div>
                </div>
            </td>
        </tr>
    ` + "`" + `;
    }).join('');
}

async function downloadKernel() {
    const form = document.getElementById('downloadKernelForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        version: formData.get('version'),
        url: formData.get('url') || ''
    };

    const { ok, data: resp } = await apiCall('/api/kernels/download', 'POST', data);
    if (ok) {
        closeModal('downloadKernelModal');
        alert('Download started. Check back in a moment.');
        setTimeout(loadKernels, 5000);
    } else {
        alert(resp.error || 'Failed to start download');
    }
}

async function downloadRootfs() {
    const form = document.getElementById('downloadRootfsForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        url: formData.get('url') || ''
    };

    const { ok, data: resp } = await apiCall('/api/rootfs/download', 'POST', data);
    if (ok) {
        closeModal('downloadRootfsModal');
        alert('Download started. Check back in a moment.');
        setTimeout(loadRootfs, 5000);
    } else {
        alert(resp.error || 'Failed to start download');
    }
}

async function uploadRootfs() {
    const nameInput = document.getElementById('uploadRootfsName');
    const fileInput = document.getElementById('uploadRootfsFile');
    const progressDiv = document.getElementById('uploadProgress');
    const progressBar = document.getElementById('uploadProgressBar');
    const progressText = document.getElementById('uploadProgressText');
    const progressPercent = document.getElementById('uploadProgressPercent');
    const submitBtn = document.getElementById('uploadSubmitBtn');
    const cancelBtn = document.getElementById('uploadCancelBtn');

    const name = nameInput.value.trim();
    const file = fileInput.files[0];

    if (!name) {
        alert('Please enter a name for the root filesystem');
        return;
    }
    if (!file) {
        alert('Please select a file to upload');
        return;
    }

    // Show progress, disable buttons
    progressDiv.style.display = 'block';
    submitBtn.disabled = true;
    cancelBtn.disabled = true;
    progressText.textContent = 'Uploading...';
    progressBar.style.width = '0%';
    progressPercent.textContent = '0%';

    const formData = new FormData();
    formData.append('name', name);
    formData.append('file', file);

    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percent + '%';
            progressPercent.textContent = percent + '%';
            const sizeMB = (e.loaded / (1024 * 1024)).toFixed(1);
            const totalMB = (e.total / (1024 * 1024)).toFixed(1);
            progressText.textContent = 'Uploading... ' + sizeMB + ' MB / ' + totalMB + ' MB';
        }
    };

    xhr.onload = function() {
        submitBtn.disabled = false;
        cancelBtn.disabled = false;

        if (xhr.status === 200) {
            const resp = JSON.parse(xhr.responseText);
            if (resp.status === 'success') {
                progressText.textContent = 'Upload complete!';
                progressBar.style.width = '100%';
                progressPercent.textContent = '100%';
                setTimeout(() => {
                    closeModal('uploadRootfsModal');
                    document.getElementById('uploadRootfsForm').reset();
                    progressDiv.style.display = 'none';
                    loadRootfs();
                }, 1000);
            } else {
                progressDiv.style.display = 'none';
                alert(resp.error || 'Upload failed');
            }
        } else {
            progressDiv.style.display = 'none';
            try {
                const resp = JSON.parse(xhr.responseText);
                alert(resp.error || 'Upload failed');
            } catch (e) {
                alert('Upload failed: ' + xhr.statusText);
            }
        }
    };

    xhr.onerror = function() {
        submitBtn.disabled = false;
        cancelBtn.disabled = false;
        progressDiv.style.display = 'none';
        alert('Upload failed: Network error');
    };

    xhr.open('POST', '/api/rootfs/upload');
    xhr.send(formData);
}

async function setDefaultKernel(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/kernels/${id}/default` + "`" + `, 'POST');
    if (ok) {
        loadKernels();
    } else {
        alert(data.error || 'Failed to set default kernel');
    }
}

async function deleteKernel(id) {
    if (!confirm('Are you sure you want to delete this kernel?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/kernels/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadKernels();
    } else {
        alert(data.error || 'Failed to delete kernel');
    }
}

async function deleteRootfs(id) {
    if (!confirm('Are you sure you want to delete this root filesystem?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/rootfs/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadRootfs();
    } else {
        alert(data.error || 'Failed to delete rootfs');
    }
}

async function openCreateVMFromRootfs(rootfsId, rootfsName) {
    // Reset form
    const form = document.getElementById('createVMFromRootfsForm');
    form.reset();

    // Clear and reload dropdowns
    const kernelSelect = document.getElementById('vmFromRootfsKernelSelect');
    const rootfsSelect = document.getElementById('vmFromRootfsSelect');
    const networkSelect = document.getElementById('vmFromRootfsNetworkSelect');
    const dataDiskSelect = document.getElementById('vmFromRootfsDataDiskSelect');

    kernelSelect.innerHTML = '<option value="">Select kernel...</option>';
    rootfsSelect.innerHTML = '<option value="">Select rootfs...</option>';
    networkSelect.innerHTML = '<option value="">No network</option>';
    dataDiskSelect.innerHTML = '<option value="">No data disk</option>';

    // Load kernels
    const kernels = await apiCall('/api/kernels');
    if (kernels.ok && kernels.data.kernels) {
        kernels.data.kernels.forEach(k => {
            const opt = document.createElement('option');
            opt.value = k.id;
            opt.textContent = k.name + ' (' + k.version + ')';
            if (k.is_default) opt.selected = true;
            kernelSelect.appendChild(opt);
        });
    }

    // Load rootfs (system disks only) and data disks
    const rootfs = await apiCall('/api/rootfs');
    if (rootfs.ok && rootfs.data.rootfs) {
        rootfs.data.rootfs.forEach(r => {
            if (r.disk_type === 'system' || !r.disk_type) {
                const opt = document.createElement('option');
                opt.value = r.id;
                opt.textContent = r.name;
                if (r.id === rootfsId) opt.selected = true;
                rootfsSelect.appendChild(opt);
            }
            if (r.disk_type === 'data') {
                const opt = document.createElement('option');
                opt.value = r.id;
                opt.textContent = r.name + ' (' + formatBytes(r.size) + ')';
                dataDiskSelect.appendChild(opt);
            }
        });
    }

    // Load networks
    const networks = await apiCall('/api/networks');
    if (networks.ok && networks.data.networks) {
        networks.data.networks.forEach(n => {
            const opt = document.createElement('option');
            opt.value = n.id;
            opt.textContent = n.name + ' (' + n.subnet + ')';
            networkSelect.appendChild(opt);
        });
    }

    // Set VM name based on rootfs name
    document.getElementById('vmFromRootfsName').value = rootfsName.replace(/\.(ext4|img|rootfs)$/i, '') + '-vm';

    openModal('createVMFromRootfsModal');
}

async function createVMFromRootfs() {
    const form = document.getElementById('createVMFromRootfsForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        vcpu: parseInt(formData.get('vcpu')) || 1,
        memory_mb: parseInt(formData.get('memory_mb')) || 512,
        kernel_id: formData.get('kernel_id'),
        rootfs_id: formData.get('rootfs_id'),
        network_id: formData.get('network_id') || '',
        dns_servers: formData.get('dns_servers') || '',
        data_disk_id: formData.get('data_disk_id') || '',
        root_password: formData.get('root_password') || ''
    };

    const { ok, data: resp } = await apiCall('/api/vms', 'POST', data);
    if (ok) {
        closeModal('createVMFromRootfsModal');
        form.reset();
        alert('VM created successfully! Go to Virtual Machines page to manage it.');
    } else {
        alert(resp.error || 'Failed to create VM');
    }
}

function openDuplicateRootfsModal(id, name) {
    document.getElementById('duplicateRootfsId').value = id;
    document.getElementById('duplicateRootfsSource').textContent = name;
    document.getElementById('duplicateRootfsName').value = name.replace(/(\.[^.]+)$/, '-copy$1');
    openModal('duplicateRootfsModal');
}

async function duplicateRootfs() {
    const id = document.getElementById('duplicateRootfsId').value;
    const name = document.getElementById('duplicateRootfsName').value.trim();

    if (!name) {
        alert('Please enter a name for the duplicate');
        return;
    }

    const { ok, data } = await apiCall(` + "`" + `/api/rootfs/${id}/duplicate` + "`" + `, 'POST', { name });
    if (ok) {
        closeModal('duplicateRootfsModal');
        loadRootfs();
    } else {
        alert(data.error || 'Failed to duplicate rootfs');
    }
}

function openRenameRootfsModal(id, name) {
    document.getElementById('renameRootfsId').value = id;
    document.getElementById('renameRootfsName').value = name;
    openModal('renameRootfsModal');
}

async function renameRootfs() {
    const id = document.getElementById('renameRootfsId').value;
    const name = document.getElementById('renameRootfsName').value.trim();

    if (!name) {
        alert('Please enter a new name');
        return;
    }

    const { ok, data } = await apiCall(` + "`" + `/api/rootfs/${id}/rename` + "`" + `, 'POST', { name });
    if (ok) {
        closeModal('renameRootfsModal');
        loadRootfs();
    } else {
        alert(data.error || 'Failed to rename rootfs');
    }
}

// Extend Disk
function openExtendDiskModal(id, name, currentSize) {
    document.getElementById('extendDiskId').value = id;
    document.getElementById('extendDiskName').value = name;
    const currentSizeMB = Math.round(currentSize / (1024 * 1024));
    document.getElementById('extendDiskCurrentSize').value = formatBytes(currentSize) + ' (' + currentSizeMB + ' MB)';
    document.getElementById('extendDiskNewSize').value = currentSizeMB + 512;
    document.getElementById('extendDiskNewSize').min = currentSizeMB + 1;
    document.getElementById('extendDiskProgress').style.display = 'none';
    document.getElementById('extendDiskBtn').disabled = false;
    openModal('extendDiskModal');
}

async function extendDisk() {
    const id = document.getElementById('extendDiskId').value;
    const newSizeMB = parseInt(document.getElementById('extendDiskNewSize').value);

    if (!newSizeMB || newSizeMB < 128) {
        alert('Please enter a valid size (minimum 128 MB)');
        return;
    }

    // Show progress
    document.getElementById('extendDiskProgress').style.display = 'block';
    document.getElementById('extendDiskBtn').disabled = true;
    document.getElementById('extendDiskProgressText').textContent = 'Extending disk...';

    const { ok, data } = await apiCall(` + "`" + `/api/rootfs/extend/${id}` + "`" + `, 'POST', { new_size_mb: newSizeMB });

    document.getElementById('extendDiskProgress').style.display = 'none';
    document.getElementById('extendDiskBtn').disabled = false;

    if (ok) {
        closeModal('extendDiskModal');
        alert('Disk extended successfully to ' + formatBytes(data.new_size || newSizeMB * 1024 * 1024));
        loadRootfs();
    } else {
        alert(data.error || 'Failed to extend disk');
    }
}

// Debian Image Builder
let debianBuildJobId = null;
let debianBuildInterval = null;

function closeDebianBuildModal() {
    if (debianBuildInterval) {
        clearInterval(debianBuildInterval);
        debianBuildInterval = null;
    }
    debianBuildJobId = null;
    closeModal('createDebianModal');
    // Reset form
    document.getElementById('createDebianForm').style.display = 'block';
    document.getElementById('debianBuildProgress').style.display = 'none';
    document.getElementById('debianBuildResult').style.display = 'none';
    document.getElementById('debianBuildBtn').disabled = false;
    document.getElementById('debianBuildBtn').innerHTML = '<span class="material-icons">build</span> Build Image';
}

async function startDebianBuild() {
    const version = document.getElementById('debianVersion').value;
    const imageName = document.getElementById('debianImageName').value.trim();
    const diskSize = parseInt(document.getElementById('debianDiskSize').value);
    const builderDir = document.getElementById('debianBuilderDir').value.trim();

    if (!imageName) {
        alert('Please enter an image name');
        return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(imageName)) {
        alert('Image name can only contain letters, numbers, dashes, and underscores');
        return;
    }

    if (diskSize < 512 || diskSize > 20480) {
        alert('Disk size must be between 512 MB and 20 GB');
        return;
    }

    // Disable form and show progress
    document.getElementById('debianBuildBtn').disabled = true;
    document.getElementById('debianBuildBtn').innerHTML = '<span class="material-icons">hourglass_empty</span> Building...';
    document.getElementById('createDebianForm').style.display = 'none';
    document.getElementById('debianBuildProgress').style.display = 'block';
    document.getElementById('debianBuildResult').style.display = 'none';

    const { ok, data } = await apiCall('/api/rootfs/build-debian', 'POST', {
        image_name: imageName,
        debian_version: version,
        disk_size_mb: diskSize,
        builder_dir: builderDir || '/home/Builder'
    });

    if (!ok) {
        document.getElementById('debianBuildProgress').style.display = 'none';
        document.getElementById('debianBuildResult').style.display = 'block';
        document.getElementById('debianBuildResult').innerHTML = '<div style="color: var(--danger);"><span class="material-icons" style="vertical-align: middle;">error</span> ' + (data.error || 'Failed to start build') + '</div>';
        document.getElementById('debianBuildBtn').disabled = false;
        document.getElementById('debianBuildBtn').innerHTML = '<span class="material-icons">build</span> Build Image';
        document.getElementById('createDebianForm').style.display = 'block';
        return;
    }

    debianBuildJobId = data.job_id;
    debianBuildInterval = setInterval(checkDebianBuildProgress, 2000);
    checkDebianBuildProgress();
}

async function checkDebianBuildProgress() {
    if (!debianBuildJobId) return;

    const { ok, data } = await apiCall('/api/rootfs/build-debian/progress?job_id=' + debianBuildJobId);
    if (!ok) return;

    const stepNames = {
        'initializing': 'Initializing',
        'checking_debootstrap': 'Checking debootstrap',
        'installing_debootstrap': 'Installing debootstrap',
        'creating_directories': 'Creating directories',
        'debootstrap': 'Running debootstrap',
        'configuring_chroot': 'Configuring system',
        'creating_image': 'Creating disk image',
        'copying_rootfs': 'Copying filesystem',
        'finalizing': 'Finalizing',
        'registering': 'Registering image',
        'completed': 'Completed'
    };

    document.getElementById('debianBuildStep').textContent = stepNames[data.step] || data.step;
    document.getElementById('debianBuildPercent').textContent = data.progress + '%';
    document.getElementById('debianBuildBar').style.width = data.progress + '%';
    document.getElementById('debianBuildMessage').textContent = data.message || '';

    if (data.status === 'completed') {
        clearInterval(debianBuildInterval);
        debianBuildInterval = null;
        document.getElementById('debianBuildProgress').style.display = 'none';
        document.getElementById('debianBuildResult').style.display = 'block';
        document.getElementById('debianBuildResult').innerHTML =
            '<div style="color: var(--success); margin-bottom: 10px;"><span class="material-icons" style="vertical-align: middle;">check_circle</span> Image created successfully!</div>' +
            '<p><strong>Image:</strong> ' + data.image_name + '.ext4</p>' +
            '<p><strong>Path:</strong> ' + data.output_path + '</p>' +
            '<p style="margin-top: 10px; color: var(--text-secondary);">Default root password is: <code>root</code></p>';
        document.getElementById('debianBuildBtn').style.display = 'none';
        document.getElementById('debianCancelBtn').textContent = 'Close';
        loadRootfs();
    } else if (data.status === 'failed') {
        clearInterval(debianBuildInterval);
        debianBuildInterval = null;
        document.getElementById('debianBuildProgress').style.display = 'none';
        document.getElementById('debianBuildResult').style.display = 'block';
        document.getElementById('debianBuildResult').innerHTML =
            '<div style="color: var(--danger);"><span class="material-icons" style="vertical-align: middle;">error</span> Build failed</div>' +
            '<p style="margin-top: 10px;">' + (data.error || 'Unknown error') + '</p>';
        document.getElementById('debianBuildBtn').disabled = false;
        document.getElementById('debianBuildBtn').innerHTML = '<span class="material-icons">build</span> Retry';
        document.getElementById('debianBuildBtn').style.display = 'inline-flex';
        document.getElementById('createDebianForm').style.display = 'block';
    }
}

// Load configured builder directory
async function loadBuilderDir() {
    const { ok, data } = await apiCall('/api/system/builder-dir');
    if (ok && data.builder_dir) {
        document.getElementById('debianBuilderDir').value = data.builder_dir;
    }
}

loadKernels();
loadRootfs();
loadBuilderDir();
</script>
`
}

func (wc *WebConsole) renderDockerPage() string {
	return `
<style>` + DockerPageCSS + `</style>

<div class="card">
    <div class="card-header">
        <h3>Docker Images</h3>
    </div>
    <div class="card-body">
        <div class="tabs">
            <button class="tab active" onclick="switchTab('search')">Registry Search</button>
            <button class="tab" onclick="switchTab('compose')">Docker Compose</button>
            <button class="tab" onclick="switchTab('jobs')">Conversion Jobs</button>
        </div>

        <!-- Registry Search Tab -->
        <div id="searchTab" class="tab-content active">
            <div class="search-box">
                <input type="text" id="searchQuery" placeholder="Search Docker Hub, Quay.io, GitLab... (e.g., nginx, ubuntu, alpine)">
                <button class="btn btn-primary" onclick="searchRegistry()">
                    <span class="material-icons">search</span>
                    Search
                </button>
            </div>
            <div id="searchResults">
                <div class="empty-state">
                    <span class="material-icons">cloud_download</span>
                    <p>Search for Docker images to convert to Firecracker rootfs</p>
                </div>
            </div>
        </div>

        <!-- Docker Compose Tab -->
        <div id="composeTab" class="tab-content">
            <div class="compose-upload-area" onclick="document.getElementById('composeFile').click()">
                <span class="material-icons">upload_file</span>
                <p>Click to upload docker-compose.yml</p>
                <small>or drag and drop the file here</small>
                <input type="file" id="composeFile" style="display: none;" accept=".yml,.yaml" onchange="handleComposeUpload(this)">
            </div>
            <div id="composePreview" style="display: none; margin-top: 20px;">
                <h4 style="margin-bottom: 10px;">Services found:</h4>
                <div id="serviceList" class="service-list"></div>
                <div style="margin-top: 15px;">
                    <button class="btn btn-primary" onclick="convertSelectedServices()">
                        <span class="material-icons">build</span>
                        Convert Selected
                    </button>
                </div>
            </div>
        </div>

        <!-- Jobs Tab -->
        <div id="jobsTab" class="tab-content">
            <div id="jobsList">
                <div class="empty-state">
                    <span class="material-icons">hourglass_empty</span>
                    <p>No conversion jobs</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Convert Image Modal -->
<div id="convertImageModal" class="modal">
    <div class="modal-content" style="max-width: 550px;">
        <div class="modal-header">
            <h3>Convert Docker Image & Create VM</h3>
            <span class="material-icons modal-close" onclick="closeModal('convertImageModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="convertImageForm">
                <input type="hidden" id="convertImageRef">
                <div class="form-group">
                    <label>Image Reference</label>
                    <input type="text" id="convertImageRefDisplay" readonly style="background: #f5f5f5;">
                </div>
                <div class="form-group">
                    <label>VM / RootFS Name</label>
                    <input type="text" id="convertOutputName" placeholder="Leave empty for auto-generated name">
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="convertInjectInit" checked style="width: auto; margin: 0;">
                        Inject minimal init script (recommended)
                    </label>
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px; margin-left: 24px;">
                        Adds /sbin/init that mounts proc, sys, dev and starts a shell
                    </small>
                </div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 15px;">VM Configuration</h4>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label>vCPUs</label>
                        <input type="number" id="convertVCPU" value="1" min="1" max="8">
                    </div>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label>Memory (MB)</label>
                        <input type="number" id="convertMemory" value="512" min="128" max="8192" step="128">
                    </div>
                </div>
                <div class="form-group" style="margin-top: 15px;">
                    <label>Network</label>
                    <select id="convertNetwork">
                        <option value="">No network</option>
                    </select>
                </div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 15px;">Data Disk (Optional)</h4>
                <div class="form-group">
                    <label>Data Disk Size (GiB)</label>
                    <input type="number" id="convertDataDiskSize" placeholder="0" min="0" max="100" value="0">
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px;">
                        Create a secondary ext4 disk for persistent data. Set to 0 to skip.
                    </small>
                </div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 15px;">Root Password</h4>
                <div class="form-group">
                    <label>Root Password</label>
                    <input type="password" id="convertRootPassword" placeholder="Set root password for VM">
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px;">
                        Set the root password for the VM. Required for Docker images without password.
                    </small>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('convertImageModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="startConversion()">Convert & Create VM</button>
        </div>
    </div>
</div>

<!-- Convert Compose Service Modal -->
<div id="convertComposeModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Convert Compose Service</h3>
            <span class="material-icons modal-close" onclick="closeModal('convertComposeModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="convertComposeForm">
                <input type="hidden" id="composeServiceName">
                <div class="form-group">
                    <label>Service</label>
                    <input type="text" id="composeServiceDisplay" readonly style="background: #f5f5f5;">
                </div>
                <div class="form-group">
                    <label>Output Name (optional)</label>
                    <input type="text" id="composeOutputName" placeholder="Leave empty for service name">
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="composeInjectInit" checked style="width: auto; margin: 0;">
                        Inject minimal init script
                    </label>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="composeUseDocker" style="width: auto; margin: 0;">
                        Use Docker daemon (if available)
                    </label>
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px; margin-left: 24px;">
                        Use local Docker to build images. If unchecked, pulls from registry.
                    </small>
                </div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid var(--border-color);">
                <h4 style="margin-bottom: 15px;">Data Disk (Optional)</h4>
                <div class="form-group">
                    <label>Data Disk Size (GiB)</label>
                    <input type="number" id="composeDataDiskSize" placeholder="0" min="0" max="100" value="0">
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px;">
                        Create a secondary ext4 disk for persistent data (volumes). Set to 0 to skip.
                    </small>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('convertComposeModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="startComposeConversion()">Convert</button>
        </div>
    </div>
</div>

<script>
let currentComposePath = '';
let composeServices = [];

function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    document.querySelector(` + "`" + `.tab[onclick="switchTab('${tab}')"]` + "`" + `).classList.add('active');
    document.getElementById(tab + 'Tab').classList.add('active');

    if (tab === 'jobs') {
        loadJobs();
    }
}

async function searchRegistry() {
    const query = document.getElementById('searchQuery').value.trim();
    if (!query) {
        alert('Please enter a search query');
        return;
    }

    const resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '<div style="text-align: center; padding: 40px;"><span class="material-icons" style="animation: spin 1s linear infinite;">refresh</span><p>Searching...</p></div>';

    try {
        const { ok, data } = await apiCall('/api/registry/search', 'POST', { query, limit: 25 });
        if (!ok) {
            resultsDiv.innerHTML = '<div class="alert alert-danger">' + (data.error || 'Search failed') + '</div>';
            return;
        }

        if (!data.results || data.results.length === 0) {
            resultsDiv.innerHTML = '<div class="empty-state"><span class="material-icons">search_off</span><p>No images found for "' + query + '"</p></div>';
            return;
        }

        resultsDiv.innerHTML = data.results.map(img => ` + "`" + `
            <div class="image-result">
                <div class="image-info">
                    <h4>${img.name}</h4>
                    <p>${decodeBase64(img.description) || 'No description'}</p>
                    <div class="image-meta">
                        <span><span class="material-icons">cloud</span>${img.registry}</span>
                        ${img.stars ? ` + "`" + `<span><span class="material-icons">star</span>${img.stars}</span>` + "`" + ` : ''}
                        ${img.pulls ? ` + "`" + `<span><span class="material-icons">download</span>${formatNumber(img.pulls)}</span>` + "`" + ` : ''}
                        ${img.official ? '<span class="badge badge-info">Official</span>' : ''}
                    </div>
                </div>
                <button class="btn btn-primary btn-sm" onclick="openConvertModal('${escapeHtml(img.full_name || img.name)}')">
                    <span class="material-icons">build</span>
                    Convert
                </button>
            </div>
        ` + "`" + `).join('');
    } catch (e) {
        resultsDiv.innerHTML = '<div class="alert alert-danger">Search failed: ' + e.message + '</div>';
    }
}

function formatNumber(num) {
    if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function decodeBase64(str) {
    if (!str) return '';
    try {
        // Check if it looks like base64 (no spaces, valid chars)
        if (/^[A-Za-z0-9+/=]+$/.test(str) && str.length > 20) {
            return atob(str);
        }
        return str;
    } catch (e) {
        return str; // Return original if decode fails
    }
}

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[m]);
}

async function openConvertModal(imageRef) {
    document.getElementById('convertImageRef').value = imageRef;
    document.getElementById('convertImageRefDisplay').value = imageRef;
    document.getElementById('convertOutputName').value = '';
    document.getElementById('convertDataDiskSize').value = '0';
    document.getElementById('convertInjectInit').checked = true;
    document.getElementById('convertVCPU').value = '1';
    document.getElementById('convertMemory').value = '512';

    // Load networks for dropdown
    const networkSelect = document.getElementById('convertNetwork');
    networkSelect.innerHTML = '<option value="">No network</option>';
    try {
        const { ok, data } = await apiCall('/api/networks');
        if (ok && data.networks) {
            data.networks.forEach(net => {
                const opt = document.createElement('option');
                opt.value = net.id;
                opt.textContent = net.name + ' (' + net.subnet + ')';
                networkSelect.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load networks:', e);
    }

    openModal('convertImageModal');
}

async function startConversion() {
    const imageRef = document.getElementById('convertImageRef').value;
    const name = document.getElementById('convertOutputName').value.trim();
    const injectMinInit = document.getElementById('convertInjectInit').checked;
    const dataDiskSize = parseInt(document.getElementById('convertDataDiskSize').value) || 0;
    const vcpu = parseInt(document.getElementById('convertVCPU').value) || 1;
    const memory = parseInt(document.getElementById('convertMemory').value) || 512;
    const networkId = document.getElementById('convertNetwork').value;
    const rootPassword = document.getElementById('convertRootPassword').value;

    const body = {
        image_ref: imageRef,
        name: name,
        inject_min_init: injectMinInit,
        create_vm: true,
        vm_vcpu: vcpu,
        vm_memory_mb: memory
    };

    if (networkId) {
        body.vm_network_id = networkId;
    }

    if (dataDiskSize > 0) {
        body.data_disk_size_gib = dataDiskSize;
    }

    if (rootPassword) {
        body.root_password = rootPassword;
    }

    try {
        const { ok, data } = await apiCall('/api/registry/convert', 'POST', body);
        if (!ok) {
            alert(data.error || 'Failed to start conversion');
            return;
        }

        closeModal('convertImageModal');
        alert('Conversion started! Job ID: ' + data.job_id + '\\nA VM will be created automatically when conversion completes.');
        switchTab('jobs');
    } catch (e) {
        alert('Failed to start conversion: ' + e.message);
    }
}

// Docker Compose handling
function handleComposeUpload(input) {
    const file = input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function(e) {
        const content = e.target.result;

        // Create a temporary file path or send content directly
        // For now, we'll save it temporarily and send the path
        try {
            // Upload compose file to server
            const formData = new FormData();
            formData.append('file', file);

            const resp = await fetch('/api/compose/upload', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();

            if (!resp.ok) {
                alert(data.error || 'Failed to upload compose file');
                return;
            }

            currentComposePath = data.path;

            // Get services
            const { ok, data: servicesData } = await apiCall('/api/compose/services', 'POST', {
                compose_path: currentComposePath
            });

            if (!ok) {
                alert(servicesData.error || 'Failed to parse compose file');
                return;
            }

            composeServices = servicesData.services || [];
            displayServices();
        } catch (e) {
            alert('Failed to process compose file: ' + e.message);
        }
    };
    reader.readAsText(file);
}

function displayServices() {
    const preview = document.getElementById('composePreview');
    const serviceList = document.getElementById('serviceList');

    if (composeServices.length === 0) {
        preview.style.display = 'none';
        return;
    }

    preview.style.display = 'block';
    serviceList.innerHTML = composeServices.map(svc => ` + "`" + `
        <div class="service-item">
            <input type="checkbox" id="svc_${svc.name}" value="${svc.name}" checked>
            <span class="service-name">${svc.name}</span>
            <span class="service-image">${svc.image || 'build context'}</span>
            <button class="btn btn-primary btn-sm" style="margin-left: 10px;" onclick="openComposeConvertModal('${svc.name}', '${escapeHtml(svc.image || '')}')">
                Convert
            </button>
        </div>
    ` + "`" + `).join('');
}

function openComposeConvertModal(serviceName, image) {
    document.getElementById('composeServiceName').value = serviceName;
    document.getElementById('composeServiceDisplay').value = serviceName + (image ? ' (' + image + ')' : '');
    document.getElementById('composeOutputName').value = '';
    document.getElementById('composeDataDiskSize').value = '0';
    document.getElementById('composeInjectInit').checked = true;
    document.getElementById('composeUseDocker').checked = false;
    openModal('convertComposeModal');
}

async function startComposeConversion() {
    const serviceName = document.getElementById('composeServiceName').value;
    const outputName = document.getElementById('composeOutputName').value.trim();
    const injectMinInit = document.getElementById('composeInjectInit').checked;
    const useDocker = document.getElementById('composeUseDocker').checked;
    const dataDiskSize = parseInt(document.getElementById('composeDataDiskSize').value) || 0;

    const body = {
        compose_path: currentComposePath,
        service_name: serviceName,
        output_name: outputName,
        inject_min_init: injectMinInit,
        use_docker: useDocker
    };

    if (dataDiskSize > 0) {
        body.data_disk_size_gib = dataDiskSize;
    }

    try {
        const { ok, data } = await apiCall('/api/compose/convert', 'POST', body);
        if (!ok) {
            alert(data.error || 'Failed to start conversion');
            return;
        }

        closeModal('convertComposeModal');
        alert('Compose conversion started! Job ID: ' + data.job_id);
        switchTab('jobs');
    } catch (e) {
        alert('Failed to start conversion: ' + e.message);
    }
}

async function convertSelectedServices() {
    const selected = [];
    composeServices.forEach(svc => {
        const checkbox = document.getElementById('svc_' + svc.name);
        if (checkbox && checkbox.checked) {
            selected.push(svc.name);
        }
    });

    if (selected.length === 0) {
        alert('Please select at least one service');
        return;
    }

    if (selected.length === 1) {
        openComposeConvertModal(selected[0], '');
    } else {
        // Multiple services - convert each one
        if (!confirm('Convert ' + selected.length + ' services? Each will create a separate rootfs.')) {
            return;
        }

        for (const serviceName of selected) {
            await apiCall('/api/compose/convert', 'POST', {
                compose_path: currentComposePath,
                service_name: serviceName,
                inject_min_init: true,
                use_docker: false
            });
        }

        alert('Started conversion for ' + selected.length + ' services');
        switchTab('jobs');
    }
}

// Jobs handling
async function loadJobs() {
    const jobsDiv = document.getElementById('jobsList');

    try {
        const { ok, data } = await apiCall('/api/registry/jobs');
        if (!ok) {
            jobsDiv.innerHTML = '<div class="alert alert-danger">' + (data.error || 'Failed to load jobs') + '</div>';
            return;
        }

        if (!data.jobs || data.jobs.length === 0) {
            jobsDiv.innerHTML = '<div class="empty-state"><span class="material-icons">hourglass_empty</span><p>No conversion jobs</p></div>';
            return;
        }

        jobsDiv.innerHTML = data.jobs.map(job => ` + "`" + `
            <div class="job-item">
                <div class="job-info">
                    <h4>${job.image_ref}</h4>
                    <div class="job-progress">
                        <span class="badge ${getStatusBadge(job.status)}">${job.status}</span>
                        ${job.status === 'running' ? ` + "`" + `
                            <div class="progress-bar">
                                <div class="progress-bar-fill" style="width: ${job.progress}%%"></div>
                            </div>
                            <span>${job.progress}%%</span>
                        ` + "`" + ` : ''}
                        <span style="color: var(--text-secondary); font-size: 12px;">${job.message}</span>
                    </div>
                    ${job.error ? ` + "`" + `<div class="alert alert-danger" style="margin-top: 10px; padding: 8px;">${job.error}</div>` + "`" + ` : ''}
                    ${job.result ? ` + "`" + `
                        <div style="margin-top: 10px; font-size: 12px; color: var(--text-secondary);">
                            RootFS ID: ${job.result.rootfs_id} | Size: ${job.result.estimated_gib} GiB
                        </div>
                    ` + "`" + ` : ''}
                </div>
            </div>
        ` + "`" + `).join('');

        // Auto-refresh if any job is running
        const hasRunning = data.jobs.some(j => j.status === 'running' || j.status === 'pending');
        if (hasRunning) {
            setTimeout(loadJobs, 3000);
        }
    } catch (e) {
        jobsDiv.innerHTML = '<div class="alert alert-danger">Failed to load jobs: ' + e.message + '</div>';
    }
}

function getStatusBadge(status) {
    switch (status) {
        case 'completed': return 'badge-success';
        case 'failed': return 'badge-danger';
        case 'running': return 'badge-info';
        case 'pending': return 'badge-warning';
        default: return 'badge-info';
    }
}

// Add enter key support for search
document.getElementById('searchQuery').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        searchRegistry();
    }
});

// Drag and drop for compose file
const uploadArea = document.querySelector('.compose-upload-area');
if (uploadArea) {
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.style.borderColor = 'var(--primary)';
        this.style.background = 'rgba(25, 118, 210, 0.05)';
    });
    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.style.borderColor = 'var(--border-color)';
        this.style.background = 'none';
    });
    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        this.style.borderColor = 'var(--border-color)';
        this.style.background = 'none';
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            document.getElementById('composeFile').files = files;
            handleComposeUpload(document.getElementById('composeFile'));
        }
    });
}
</script>
`
}

func (wc *WebConsole) renderLogsPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>System Logs</h3>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th style="white-space: nowrap;">Date</th>
                    <th>VM</th>
                    <th>Level</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody id="logList">
                <tr><td colspan="4">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
async function loadLogs() {
    const { ok, data } = await apiCall('/api/logs?limit=100');
    if (!ok) return;

    const tbody = document.getElementById('logList');
    if (!data.logs || data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><span class="material-icons">article</span><p>No logs</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.logs.map(log => ` + "`" + `
        <tr>
            <td style="white-space: nowrap;">${formatDate(log.created_at)}</td>
            <td><a href="/vms/${log.vm_id}">${log.vm_id.substring(0, 8)}...</a></td>
            <td><span class="badge badge-${log.level === 'error' ? 'danger' : log.level === 'warning' ? 'warning' : 'info'}">${log.level}</span></td>
            <td>${log.message}</td>
        </tr>
    ` + "`" + `).join('');
}

loadLogs();
setInterval(loadLogs, 10000);
</script>
`
}

func (wc *WebConsole) renderSettingsPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>System Status</h3>
        <button class="btn btn-secondary btn-sm" onclick="loadSystemStatus()">
            <span class="material-icons">refresh</span> Refresh
        </button>
    </div>
    <div class="card-body">
        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">FireCrackManager</h4>
                <table style="width: 100%;">
                    <tr><td><strong>Version:</strong></td><td id="fcmVersion">-</td></tr>
                    <tr><td><strong>Build Date:</strong></td><td id="fcmBuildDate">-</td></tr>
                    <tr><td><strong>Uptime:</strong></td><td id="fcmUptime">-</td></tr>
                </table>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">Firecracker</h4>
                <table style="width: 100%;">
                    <tr>
                        <td><strong>Version:</strong></td>
                        <td>
                            <span id="fcVersion">-</span>
                            <span id="fcUpdateBadge" class="badge badge-success" style="display: none; margin-left: 8px;">Update available</span>
                        </td>
                    </tr>
                    <tr><td><strong>Latest:</strong></td><td id="fcLatestVersion">-</td></tr>
                    <tr><td><strong>Last Checked:</strong></td><td id="fcLastChecked">-</td></tr>
                    <tr><td><strong>Path:</strong></td><td id="fcPath">-</td></tr>
                    <tr><td><strong>Status:</strong></td><td id="fcStatus">-</td></tr>
                </table>
                <div id="upgradeSection" style="margin-top: 15px; display: none;">
                    <button class="btn btn-primary" onclick="upgradeFirecracker()" id="upgradeBtn">
                        <span class="material-icons">system_update</span> Upgrade Firecracker
                    </button>
                    <p style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
                        Note: All VMs must be stopped before upgrading.
                    </p>
                </div>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">System</h4>
                <table style="width: 100%;">
                    <tr><td><strong>Hostname:</strong></td><td id="sysHostname">-</td></tr>
                    <tr><td><strong>OS:</strong></td><td id="sysOS">-</td></tr>
                    <tr><td><strong>Architecture:</strong></td><td id="sysArch">-</td></tr>
                    <tr><td><strong>CPUs:</strong></td><td id="sysCPU">-</td></tr>
                    <tr><td><strong>Go Version:</strong></td><td id="sysGoVersion">-</td></tr>
                </table>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">KVM</h4>
                <table style="width: 100%;">
                    <tr><td><strong>Available:</strong></td><td id="kvmAvailable">-</td></tr>
                    <tr><td><strong>Path:</strong></td><td id="kvmPath">-</td></tr>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Configuration</h3>
    </div>
    <div class="card-body">
        <table style="width: 100%; max-width: 600px;">
            <tr>
                <td><strong>Proxy Settings:</strong></td>
                <td>
                    <a href="#" onclick="openModal('proxyModal'); return false;" style="color: var(--primary); text-decoration: none;">
                        <span id="proxyStatusText">Loading...</span>
                        <span class="material-icons" style="font-size: 16px; vertical-align: middle;">edit</span>
                    </a>
                </td>
            </tr>
            <tr><td><strong>Config File:</strong></td><td>/etc/firecrackmanager/settings.json</td></tr>
            <tr><td><strong>Data Directory:</strong></td><td>/var/lib/firecrackmanager</td></tr>
            <tr><td><strong>Log File:</strong></td><td>/var/log/firecrackmanager/firecrackmanager.log</td></tr>
            <tr><td><strong>Firecracker Binary:</strong></td><td>/usr/sbin/firecracker</td></tr>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Jailer Configuration</h3>
        <span id="jailerStatusBadge" class="badge badge-secondary">Loading...</span>
    </div>
    <div class="card-body">
        <p style="color: var(--text-secondary); margin-bottom: 20px;">
            The Firecracker jailer provides enhanced security isolation for VMs using chroot, namespaces, and cgroups.
        </p>
        <form id="jailerForm" style="max-width: 600px;">
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 10px;">
                    <input type="checkbox" id="jailerEnabled" name="enabled" style="width: auto;">
                    <span>Enable Jailer</span>
                </label>
                <small style="color: var(--text-secondary);">When enabled, VMs will run in isolated jail environments</small>
            </div>
            <div id="jailerSettings" style="display: none;">
                <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div class="form-group">
                        <label>Jailer Binary Path</label>
                        <input type="text" id="jailerPath" name="jailer_path" value="/usr/sbin/jailer">
                        <small style="color: var(--text-secondary);">Path to the jailer executable</small>
                    </div>
                    <div class="form-group">
                        <label>Chroot Base Directory</label>
                        <input type="text" id="jailerChrootBase" name="chroot_base" value="/srv/jailer">
                        <small style="color: var(--text-secondary);">Base directory for jail environments</small>
                    </div>
                    <div class="form-group">
                        <label>UID</label>
                        <input type="number" id="jailerUID" name="uid" value="1000" min="0">
                        <small style="color: var(--text-secondary);">User ID for jailed processes</small>
                    </div>
                    <div class="form-group">
                        <label>GID</label>
                        <input type="number" id="jailerGID" name="gid" value="1000" min="0">
                        <small style="color: var(--text-secondary);">Group ID for jailed processes</small>
                    </div>
                    <div class="form-group">
                        <label>Cgroup Version</label>
                        <select id="jailerCgroupVer" name="cgroup_version">
                            <option value="2">v2 (unified)</option>
                            <option value="1">v1 (legacy)</option>
                        </select>
                        <small style="color: var(--text-secondary);">Control group version for resource limits</small>
                    </div>
                    <div class="form-group">
                        <label>Network Namespace</label>
                        <input type="text" id="jailerNetNS" name="netns" placeholder="Optional">
                        <small style="color: var(--text-secondary);">Path to network namespace (leave empty for default)</small>
                    </div>
                </div>
                <div class="form-group" style="margin-top: 15px;">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" id="jailerDaemonize" name="daemonize" style="width: auto;" checked>
                        <span>Daemonize</span>
                    </label>
                    <small style="color: var(--text-secondary);">Run jailer as a daemon (recommended)</small>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" id="jailerNewPidNS" name="new_pid_ns" style="width: auto;" checked>
                        <span>New PID Namespace</span>
                    </label>
                    <small style="color: var(--text-secondary);">Run VM in a new PID namespace for isolation</small>
                </div>
                <div style="background: var(--bg-tertiary); padding: 15px; border-radius: 8px; margin-top: 15px;">
                    <h4 style="margin-bottom: 10px; color: var(--text-secondary);">Resource Limits (Optional)</h4>
                    <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label>File Size Limit (bytes)</label>
                            <input type="number" id="jailerFsize" name="fsize" value="0" min="0">
                            <small style="color: var(--text-secondary);">0 = unlimited</small>
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label>Max Open Files</label>
                            <input type="number" id="jailerNoFile" name="no_file" value="0" min="0">
                            <small style="color: var(--text-secondary);">0 = default</small>
                        </div>
                    </div>
                </div>
            </div>
            <div style="margin-top: 20px;">
                <button type="submit" class="btn btn-primary">
                    <span class="material-icons">save</span> Save Jailer Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Proxy Configuration Modal -->
<div id="proxyModal" class="modal">
    <div class="modal-content" style="max-width: 550px;">
        <div class="modal-header">
            <h2>Proxy Configuration</h2>
            <span class="material-icons modal-close" onclick="closeModal('proxyModal')">close</span>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-secondary); margin-bottom: 20px;">
                Configure HTTP proxy for all downloads (kernel images, rootfs, Firecracker updates).
            </p>
            <form id="proxyForm">
                <div class="form-group">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="proxyEnabled" name="enabled" style="width: auto; margin-right: 8px;">
                        Enable Proxy
                    </label>
                </div>
                <div id="proxySettings" style="display: none;">
                    <div class="form-group">
                        <label>Proxy URL</label>
                        <input type="text" id="proxyUrl" name="url" placeholder="http://proxy.example.com:8080">
                        <small style="color: var(--text-secondary);">e.g., http://proxy:8080 or socks5://proxy:1080</small>
                    </div>
                    <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" id="proxyUsername" name="username" placeholder="Optional">
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" id="proxyPassword" name="password" placeholder="Leave empty to keep">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>No Proxy (bypass list)</label>
                        <input type="text" id="proxyNoProxy" name="no_proxy" placeholder="localhost,127.0.0.1,.internal">
                        <small style="color: var(--text-secondary);">Comma-separated list of hosts to bypass</small>
                    </div>
                    <div style="margin-top: 15px;">
                        <button type="button" class="btn btn-secondary btn-sm" onclick="testProxyConnection()">
                            <span class="material-icons">network_check</span> Test Connection
                        </button>
                        <span id="proxyTestResult" style="margin-left: 10px;"></span>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('proxyModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveProxyConfig()">
                <span class="material-icons">save</span> Save
            </button>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Change Password</h3>
    </div>
    <div class="card-body">
        <form id="passwordForm" style="max-width: 400px;">
            <div class="form-group">
                <label>Current Password</label>
                <input type="password" name="current_password" required>
            </div>
            <div class="form-group">
                <label>New Password</label>
                <input type="password" name="new_password" required>
            </div>
            <div class="form-group">
                <label>Confirm New Password</label>
                <input type="password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn btn-primary">Update Password</button>
        </form>
    </div>
</div>

<script>
async function loadJailerConfig() {
    const { ok, data } = await apiCall('/api/system/jailer');
    const badge = document.getElementById('jailerStatusBadge');
    const settingsDiv = document.getElementById('jailerSettings');

    if (ok) {
        // Update availability badge
        if (data.available) {
            badge.className = 'badge badge-success';
            badge.textContent = 'Available';
        } else {
            badge.className = 'badge badge-warning';
            badge.textContent = 'Not Available';
        }

        // Populate form fields
        const config = data.config || {};
        document.getElementById('jailerEnabled').checked = config.enabled || false;
        document.getElementById('jailerPath').value = config.jailer_path || '/usr/sbin/jailer';
        document.getElementById('jailerChrootBase').value = config.chroot_base || '/srv/jailer';
        document.getElementById('jailerUID').value = config.uid || 1000;
        document.getElementById('jailerGID').value = config.gid || 1000;
        document.getElementById('jailerCgroupVer').value = config.cgroup_version || 2;
        document.getElementById('jailerNetNS').value = config.netns || '';
        document.getElementById('jailerDaemonize').checked = config.daemonize !== false;
        document.getElementById('jailerNewPidNS').checked = config.new_pid_ns !== false;
        document.getElementById('jailerFsize').value = config.resource_limits?.fsize || 0;
        document.getElementById('jailerNoFile').value = config.resource_limits?.no_file || 0;

        // Show/hide settings based on enabled state
        settingsDiv.style.display = config.enabled ? 'block' : 'none';
    } else {
        badge.className = 'badge badge-danger';
        badge.textContent = 'Error';
    }
}

document.getElementById('jailerEnabled').addEventListener('change', function() {
    document.getElementById('jailerSettings').style.display = this.checked ? 'block' : 'none';
});

document.getElementById('jailerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const config = {
        enabled: document.getElementById('jailerEnabled').checked,
        jailer_path: document.getElementById('jailerPath').value,
        chroot_base: document.getElementById('jailerChrootBase').value,
        uid: parseInt(document.getElementById('jailerUID').value) || 1000,
        gid: parseInt(document.getElementById('jailerGID').value) || 1000,
        cgroup_version: parseInt(document.getElementById('jailerCgroupVer').value) || 2,
        netns: document.getElementById('jailerNetNS').value,
        daemonize: document.getElementById('jailerDaemonize').checked,
        new_pid_ns: document.getElementById('jailerNewPidNS').checked,
        resource_limits: {
            fsize: parseInt(document.getElementById('jailerFsize').value) || 0,
            no_file: parseInt(document.getElementById('jailerNoFile').value) || 0
        }
    };

    const { ok, data } = await apiCall('/api/system/jailer', 'PUT', config);
    if (ok) {
        alert('Jailer configuration saved successfully');
        loadJailerConfig();
    } else {
        alert(data.error || 'Failed to save jailer configuration');
    }
});

async function loadSystemStatus() {
    // Load system status (fast - local only)
    const { ok, data } = await apiCall('/api/system/status');
    if (ok) {
        // FireCrackManager info
        document.getElementById('fcmVersion').textContent = data.firecrackmanager?.version || '-';
        document.getElementById('fcmBuildDate').textContent = data.firecrackmanager?.build_date || 'development';

        // Format uptime
        const uptime = data.uptime_seconds || 0;
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        document.getElementById('fcmUptime').textContent = hours + 'h ' + minutes + 'm';

        // Firecracker info
        document.getElementById('fcVersion').textContent = data.firecracker?.version || 'not installed';
        document.getElementById('fcPath').textContent = data.firecracker?.path || '-';
        document.getElementById('fcStatus').innerHTML = data.firecracker?.installed
            ? '<span class="badge badge-success">Installed</span>'
            : '<span class="badge badge-danger">Not Installed</span>';

        // System info
        document.getElementById('sysHostname').textContent = data.system?.hostname || '-';
        document.getElementById('sysOS').textContent = data.system?.os || '-';
        document.getElementById('sysArch').textContent = data.system?.arch || '-';
        document.getElementById('sysCPU').textContent = data.system?.num_cpu || '-';
        document.getElementById('sysGoVersion').textContent = data.system?.go_version || '-';

        // KVM info
        document.getElementById('kvmAvailable').innerHTML = data.kvm?.available
            ? '<span class="badge badge-success">Yes</span>'
            : '<span class="badge badge-danger">No</span>';
        document.getElementById('kvmPath').textContent = data.kvm?.path || '-';
    }
}

async function checkFirecrackerUpdate() {
    // Get cached Firecracker version info (fast - reads from local cache)
    const checkResp = await apiCall('/api/system/firecracker/check');
    if (checkResp.ok) {
        document.getElementById('fcLatestVersion').textContent = checkResp.data.latest_version || 'not checked yet';

        // Format last checked time
        if (checkResp.data.checked_at) {
            const checkedAt = new Date(checkResp.data.checked_at);
            if (checkedAt.getTime() > 0) {
                document.getElementById('fcLastChecked').textContent = checkedAt.toLocaleString();
            } else {
                document.getElementById('fcLastChecked').textContent = 'never';
            }
        } else {
            document.getElementById('fcLastChecked').textContent = 'never';
        }

        if (checkResp.data.update_available) {
            document.getElementById('fcUpdateBadge').style.display = 'inline-block';
            document.getElementById('upgradeSection').style.display = 'block';
        } else {
            document.getElementById('fcUpdateBadge').style.display = 'none';
            document.getElementById('upgradeSection').style.display = 'none';
        }
    } else {
        document.getElementById('fcLatestVersion').textContent = 'check failed';
        document.getElementById('fcLastChecked').textContent = '-';
    }
}

async function upgradeFirecracker() {
    if (!confirm('Are you sure you want to upgrade Firecracker? All VMs must be stopped.')) {
        return;
    }

    const btn = document.getElementById('upgradeBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Upgrading...';

    const { ok, data } = await apiCall('/api/system/firecracker/upgrade', 'POST');
    if (ok) {
        alert('Firecracker upgrade started. Please wait and refresh to see the new version.');
        setTimeout(() => {
            loadSystemStatus();
            checkFirecrackerUpdate();
        }, 10000);
    } else {
        alert(data.error || 'Failed to upgrade Firecracker');
        btn.disabled = false;
        btn.innerHTML = '<span class="material-icons">system_update</span> Upgrade Firecracker';
    }
}

document.getElementById('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const newPass = form.new_password.value;
    const confirmPass = form.confirm_password.value;

    if (newPass !== confirmPass) {
        alert('Passwords do not match');
        return;
    }

    // Note: This would need backend implementation for current user password change
    alert('Password change functionality requires backend implementation');
});

// Proxy configuration functions
async function loadProxyConfig() {
    const { ok, data } = await apiCall('/api/system/proxy');
    const statusText = document.getElementById('proxyStatusText');
    const settingsDiv = document.getElementById('proxySettings');

    if (ok) {
        const config = data.config || {};
        document.getElementById('proxyEnabled').checked = config.enabled || false;
        document.getElementById('proxyUrl').value = config.url || '';
        document.getElementById('proxyUsername').value = config.username || '';
        document.getElementById('proxyPassword').value = '';  // Don't show existing password
        document.getElementById('proxyNoProxy').value = config.no_proxy || '';

        // Update status text in Configuration table
        if (config.enabled && config.url) {
            statusText.innerHTML = '<span style="color: var(--success);">Enabled</span> - ' + config.url;
        } else if (config.enabled) {
            statusText.innerHTML = '<span style="color: var(--warning);">Enabled (no URL)</span>';
        } else {
            statusText.textContent = 'Disabled';
        }

        // Show/hide settings based on enabled state
        if (settingsDiv) {
            settingsDiv.style.display = config.enabled ? 'block' : 'none';
        }
    } else {
        statusText.innerHTML = '<span style="color: var(--danger);">Error loading</span>';
    }
}

document.getElementById('proxyEnabled').addEventListener('change', function() {
    document.getElementById('proxySettings').style.display = this.checked ? 'block' : 'none';
});

async function saveProxyConfig() {
    const config = {
        enabled: document.getElementById('proxyEnabled').checked,
        url: document.getElementById('proxyUrl').value,
        username: document.getElementById('proxyUsername').value,
        password: document.getElementById('proxyPassword').value,
        no_proxy: document.getElementById('proxyNoProxy').value
    };

    const { ok, data } = await apiCall('/api/system/proxy', 'PUT', config);
    if (ok) {
        closeModal('proxyModal');
        loadProxyConfig();
    } else {
        alert(data.error || 'Failed to save proxy configuration');
    }
}

async function testProxyConnection() {
    const resultSpan = document.getElementById('proxyTestResult');
    resultSpan.innerHTML = '<span style="color: var(--text-secondary);">Testing...</span>';

    const { ok, data } = await apiCall('/api/system/proxy/test', 'POST');
    if (ok && data.success) {
        resultSpan.innerHTML = '<span style="color: var(--success);">&#10003; OK</span>';
    } else {
        const error = data.error || 'Failed';
        resultSpan.innerHTML = '<span style="color: var(--danger);">&#10007; ' + error + '</span>';
    }
}

// Load system status immediately (fast)
loadSystemStatus();
// Load jailer configuration
loadJailerConfig();
// Load proxy configuration
loadProxyConfig();
// Load cached version info (fast - reads from local JSON cache)
checkFirecrackerUpdate();
// Refresh local status every 30 seconds
setInterval(loadSystemStatus, 30000);
</script>
`
}

func (wc *WebConsole) renderUsersPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Users</h3>
        <button class="btn btn-primary" onclick="openModal('createUserModal')">
            <span class="material-icons">person_add</span>
            Add User
        </button>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="userList">
                <tr><td colspan="5">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="createUserModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create User</h3>
            <span class="material-icons modal-close" onclick="closeModal('createUserModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createUserForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email">
                </div>
                <div class="form-group">
                    <label>Role</label>
                    <select name="role">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createUserModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createUser()">Create</button>
        </div>
    </div>
</div>

<script>
async function loadUsers() {
    const { ok, data } = await apiCall('/api/users');
    if (!ok) return;

    const tbody = document.getElementById('userList');
    if (!data.users || data.users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5">No users</td></tr>';
        return;
    }

    tbody.innerHTML = data.users.map(user => ` + "`" + `
        <tr>
            <td>${user.username}</td>
            <td>${user.email || '-'}</td>
            <td><span class="badge badge-${user.role === 'admin' ? 'info' : 'secondary'}">${user.role}</span></td>
            <td><span class="badge badge-${user.active ? 'success' : 'danger'}">${user.active ? 'Active' : 'Disabled'}</span></td>
            <td class="actions">
                <button class="btn btn-secondary btn-sm" onclick="resetPassword(${user.id})">Reset Password</button>
                <button class="btn btn-danger btn-sm" onclick="deleteUser(${user.id})">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function createUser() {
    const form = document.getElementById('createUserForm');
    const formData = new FormData(form);
    const data = {
        username: formData.get('username'),
        password: formData.get('password'),
        email: formData.get('email') || '',
        role: formData.get('role')
    };

    const { ok, data: resp } = await apiCall('/api/users', 'POST', data);
    if (ok) {
        closeModal('createUserModal');
        form.reset();
        loadUsers();
    } else {
        alert(resp.error || 'Failed to create user');
    }
}

async function resetPassword(id) {
    const newPassword = prompt('Enter new password:');
    if (!newPassword) return;

    const { ok, data } = await apiCall(` + "`" + `/api/users/${id}/password` + "`" + `, 'POST', { password: newPassword });
    if (ok) {
        alert('Password updated');
    } else {
        alert(data.error || 'Failed to update password');
    }
}

async function deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/users/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadUsers();
    } else {
        alert(data.error || 'Failed to delete user');
    }
}

loadUsers();
</script>
`
}

func (wc *WebConsole) renderGroupsPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Groups</h3>
        <button class="btn btn-primary" onclick="openModal('createGroupModal')">
            <span class="material-icons">group_add</span>
            Add Group
        </button>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Permissions</th>
                    <th>Members</th>
                    <th>VMs</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="groupList">
                <tr><td colspan="6">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="createGroupModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Group</h3>
            <span class="material-icons modal-close" onclick="closeModal('createGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createGroupForm">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" required placeholder="Group name">
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input type="text" name="description" placeholder="Optional description">
                </div>
                <div class="form-group">
                    <label>Permissions</label>
                    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-top: 8px;">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_start" checked style="width: auto; margin-right: 5px;"> Start
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_stop" checked style="width: auto; margin-right: 5px;"> Stop
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_console" checked style="width: auto; margin-right: 5px;"> Console
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_edit" style="width: auto; margin-right: 5px;"> Edit
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_snapshot" style="width: auto; margin-right: 5px;"> Snapshot
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_disk" style="width: auto; margin-right: 5px;"> Disk
                        </label>
                    </div>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Select which operations group members can perform on assigned VMs.</small>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createGroupModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createGroup()">Create</button>
        </div>
    </div>
</div>

<div id="editGroupModal" class="modal">
    <div class="modal-content" style="max-width: 700px;">
        <div class="modal-header">
            <h3>Edit Group: <span id="editGroupName"></span></h3>
            <span class="material-icons modal-close" onclick="closeModal('editGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="editGroupId">

            <div style="display: flex; gap: 20px;">
                <!-- Members Section -->
                <div style="flex: 1;">
                    <h4 style="margin-bottom: 10px;">Members</h4>
                    <div style="margin-bottom: 10px;">
                        <select id="addMemberSelect" style="width: calc(100% - 80px); display: inline-block;">
                            <option value="">Select user...</option>
                        </select>
                        <button class="btn btn-primary btn-sm" onclick="addMember()">Add</button>
                    </div>
                    <div id="membersList" style="max-height: 200px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;">
                        <p style="color: var(--text-secondary);">No members</p>
                    </div>
                </div>

                <!-- VMs Section -->
                <div style="flex: 1;">
                    <h4 style="margin-bottom: 10px;">Assigned VMs</h4>
                    <div style="margin-bottom: 10px;">
                        <select id="addVmSelect" style="width: calc(100% - 80px); display: inline-block;">
                            <option value="">Select VM...</option>
                        </select>
                        <button class="btn btn-primary btn-sm" onclick="addVmToGroup()">Add</button>
                    </div>
                    <div id="vmsList" style="max-height: 200px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;">
                        <p style="color: var(--text-secondary);">No VMs assigned</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('editGroupModal')">Close</button>
        </div>
    </div>
</div>

<script>
let allUsers = [];
let allVMs = [];

async function loadGroups() {
    const { ok, data } = await apiCall('/api/groups');
    if (!ok) return;

    const tbody = document.getElementById('groupList');
    if (!data.groups || data.groups.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><span class="material-icons">group_work</span><p>No groups</p></td></tr>';
        return;
    }

    // Fetch member and VM counts for each group
    const groupsWithCounts = await Promise.all(data.groups.map(async (group) => {
        const [membersResp, vmsResp] = await Promise.all([
            apiCall(` + "`" + `/api/groups/${group.id}/members` + "`" + `),
            apiCall(` + "`" + `/api/groups/${group.id}/vms` + "`" + `)
        ]);
        return {
            ...group,
            memberCount: membersResp.ok && membersResp.data.members ? membersResp.data.members.length : 0,
            vmCount: vmsResp.ok && vmsResp.data.vms ? vmsResp.data.vms.length : 0
        };
    }));

    tbody.innerHTML = groupsWithCounts.map(group => ` + "`" + `
        <tr>
            <td><strong>${group.name}</strong></td>
            <td>${group.description || '-'}</td>
            <td>
                ${group.permissions.split(',').map(p => ` + "`" + `<span class="badge badge-info" style="margin: 1px;">${p.trim()}</span>` + "`" + `).join('')}
            </td>
            <td><span class="badge badge-secondary">${group.memberCount}</span></td>
            <td><span class="badge badge-secondary">${group.vmCount}</span></td>
            <td class="actions">
                <button class="btn btn-secondary btn-sm" onclick="editGroup('${group.id}')" title="Edit">
                    <span class="material-icons">edit</span>
                </button>
                <button class="btn btn-danger btn-sm" onclick="deleteGroup('${group.id}')" title="Delete">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

function getPermissionsFromForm() {
    const perms = [];
    if (document.querySelector('[name="perm_start"]').checked) perms.push('start');
    if (document.querySelector('[name="perm_stop"]').checked) perms.push('stop');
    if (document.querySelector('[name="perm_console"]').checked) perms.push('console');
    if (document.querySelector('[name="perm_edit"]').checked) perms.push('edit');
    if (document.querySelector('[name="perm_snapshot"]').checked) perms.push('snapshot');
    if (document.querySelector('[name="perm_disk"]').checked) perms.push('disk');
    return perms.join(',');
}

async function createGroup() {
    const form = document.getElementById('createGroupForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        description: formData.get('description') || '',
        permissions: getPermissionsFromForm()
    };

    const { ok, data: resp } = await apiCall('/api/groups', 'POST', data);
    if (ok) {
        closeModal('createGroupModal');
        form.reset();
        loadGroups();
    } else {
        alert(resp.error || 'Failed to create group');
    }
}

async function editGroup(groupId) {
    // Load group details
    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}` + "`" + `);
    if (!ok) {
        alert(data.error || 'Failed to load group');
        return;
    }

    document.getElementById('editGroupId').value = groupId;
    document.getElementById('editGroupName').textContent = data.name;

    // Load all users and VMs for dropdowns
    const [usersResp, vmsResp] = await Promise.all([
        apiCall('/api/users'),
        apiCall('/api/vms')
    ]);
    allUsers = usersResp.ok && usersResp.data.users ? usersResp.data.users : [];
    allVMs = vmsResp.ok && vmsResp.data.vms ? vmsResp.data.vms : [];

    // Load current members and VMs
    await refreshGroupDetails(groupId);

    openModal('editGroupModal');
}

async function refreshGroupDetails(groupId) {
    const [membersResp, groupVmsResp] = await Promise.all([
        apiCall(` + "`" + `/api/groups/${groupId}/members` + "`" + `),
        apiCall(` + "`" + `/api/groups/${groupId}/vms` + "`" + `)
    ]);

    const currentMembers = membersResp.ok && membersResp.data.members ? membersResp.data.members : [];
    const currentVMs = groupVmsResp.ok && groupVmsResp.data.vms ? groupVmsResp.data.vms : [];
    const memberIds = currentMembers.map(m => m.user_id);
    const vmIds = currentVMs.map(v => v.vm_id);

    // Populate member dropdown (exclude already added)
    const memberSelect = document.getElementById('addMemberSelect');
    memberSelect.innerHTML = '<option value="">Select user...</option>';
    allUsers.filter(u => !memberIds.includes(u.id)).forEach(u => {
        memberSelect.innerHTML += ` + "`" + `<option value="${u.id}">${u.username} (${u.role})</option>` + "`" + `;
    });

    // Populate VM dropdown (exclude already added)
    const vmSelect = document.getElementById('addVmSelect');
    vmSelect.innerHTML = '<option value="">Select VM...</option>';
    allVMs.filter(v => !vmIds.includes(v.id)).forEach(v => {
        vmSelect.innerHTML += ` + "`" + `<option value="${v.id}">${v.name}</option>` + "`" + `;
    });

    // Show members list
    const membersList = document.getElementById('membersList');
    if (currentMembers.length === 0) {
        membersList.innerHTML = '<p style="color: var(--text-secondary);">No members</p>';
    } else {
        membersList.innerHTML = currentMembers.map(m => ` + "`" + `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid var(--border-color);">
                <span>${m.username}</span>
                <button class="btn btn-danger btn-xs" onclick="removeMember(${m.user_id})">
                    <span class="material-icons" style="font-size: 14px;">close</span>
                </button>
            </div>
        ` + "`" + `).join('');
    }

    // Show VMs list
    const vmsList = document.getElementById('vmsList');
    if (currentVMs.length === 0) {
        vmsList.innerHTML = '<p style="color: var(--text-secondary);">No VMs assigned</p>';
    } else {
        vmsList.innerHTML = currentVMs.map(v => ` + "`" + `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid var(--border-color);">
                <span>${v.vm_name}</span>
                <button class="btn btn-danger btn-xs" onclick="removeVmFromGroup('${v.vm_id}')">
                    <span class="material-icons" style="font-size: 14px;">close</span>
                </button>
            </div>
        ` + "`" + `).join('');
    }
}

async function addMember() {
    const groupId = document.getElementById('editGroupId').value;
    const userId = document.getElementById('addMemberSelect').value;
    if (!userId) return;

    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}/members` + "`" + `, 'POST', { user_id: parseInt(userId) });
    if (ok) {
        await refreshGroupDetails(groupId);
        loadGroups();
    } else {
        alert(data.error || 'Failed to add member');
    }
}

async function removeMember(userId) {
    const groupId = document.getElementById('editGroupId').value;
    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}/members/${userId}` + "`" + `, 'DELETE');
    if (ok) {
        await refreshGroupDetails(groupId);
        loadGroups();
    } else {
        alert(data.error || 'Failed to remove member');
    }
}

async function addVmToGroup() {
    const groupId = document.getElementById('editGroupId').value;
    const vmId = document.getElementById('addVmSelect').value;
    if (!vmId) return;

    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}/vms` + "`" + `, 'POST', { vm_id: vmId });
    if (ok) {
        await refreshGroupDetails(groupId);
        loadGroups();
    } else {
        alert(data.error || 'Failed to add VM');
    }
}

async function removeVmFromGroup(vmId) {
    const groupId = document.getElementById('editGroupId').value;
    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}/vms/${vmId}` + "`" + `, 'DELETE');
    if (ok) {
        await refreshGroupDetails(groupId);
        loadGroups();
    } else {
        alert(data.error || 'Failed to remove VM');
    }
}

async function deleteGroup(groupId) {
    if (!confirm('Are you sure you want to delete this group?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}` + "`" + `, 'DELETE');
    if (ok) {
        loadGroups();
    } else {
        alert(data.error || 'Failed to delete group');
    }
}

loadGroups();
</script>
`
}

func (wc *WebConsole) renderStandaloneConsolePage(vmID string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VM Console - FireCrackManager</title>
    <link href="/assets/material-icons.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/xterm.css">
    <style>`+ConsolePageCSS+`</style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <span class="material-icons">terminal</span>
            <h1>VM Console</h1>
            <span class="vm-info">ID: %s</span>
        </div>
        <div class="status">
            <span class="status-dot" id="statusDot"></span>
            <span id="statusText">Connecting...</span>
            <button class="btn btn-secondary" onclick="reconnect()" title="Reconnect">
                <span class="material-icons">refresh</span>
            </button>
            <button class="btn btn-secondary" onclick="window.close()" title="Close">
                <span class="material-icons">close</span>
            </button>
        </div>
    </div>
    <div id="terminal-container">
        <div id="terminal"></div>
    </div>

    <script src="/assets/xterm.min.js"></script>
    <script src="/assets/xterm-addon-fit.min.js"></script>
    <script>
        const vmId = '%s';
        let term = null;
        let ws = null;
        let fitAddon = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;

        function updateStatus(status, text) {
            const dot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            dot.className = 'status-dot ' + status;
            statusText.textContent = text;
        }

        function initTerminal() {
            term = new Terminal({
                cursorBlink: true,
                fontSize: 14,
                fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                logLevel: 'off',
                cols: 80,
                rows: 24,
                convertEol: true,
                scrollback: 5000,
                theme: {
                    background: '#1e1e1e',
                    foreground: '#d4d4d4',
                    cursor: '#d4d4d4',
                    selection: '#264f78',
                    black: '#000000',
                    red: '#cd3131',
                    green: '#0dbc79',
                    yellow: '#e5e510',
                    blue: '#2472c8',
                    magenta: '#bc3fbc',
                    cyan: '#11a8cd',
                    white: '#e5e5e5',
                    brightBlack: '#666666',
                    brightRed: '#f14c4c',
                    brightGreen: '#23d18b',
                    brightYellow: '#f5f543',
                    brightBlue: '#3b8eea',
                    brightMagenta: '#d670d6',
                    brightCyan: '#29b8db',
                    brightWhite: '#ffffff'
                }
            });

            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);

            const container = document.getElementById('terminal');
            term.open(container);
            fitAddon.fit();

            // Send input to WebSocket
            term.onData(function(data) {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(data);
                }
            });
        }

        function connect() {
            updateStatus('connecting', 'Connecting...');

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/api/vms/console/' + vmId;

            ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';

            ws.onopen = function() {
                updateStatus('connected', 'Connected');
                reconnectAttempts = 0;
                term.writeln('\r\n\x1b[32mConnected to VM console\x1b[0m\r\n');
            };

            ws.onmessage = function(event) {
                const data = new Uint8Array(event.data);
                term.write(data);
            };

            ws.onclose = function() {
                updateStatus('disconnected', 'Disconnected');
                term.writeln('\r\n\x1b[31mConnection closed\x1b[0m');

                // Auto-reconnect
                if (reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    term.writeln('\x1b[33mReconnecting in 3 seconds... (attempt ' + reconnectAttempts + '/' + maxReconnectAttempts + ')\x1b[0m\r\n');
                    setTimeout(connect, 3000);
                } else {
                    term.writeln('\x1b[31mMax reconnection attempts reached. Click Reconnect to try again.\x1b[0m\r\n');
                }
            };

            ws.onerror = function(error) {
                updateStatus('disconnected', 'Error');
                term.writeln('\r\n\x1b[31mWebSocket error\x1b[0m\r\n');
            };
        }

        function reconnect() {
            if (ws) {
                ws.close();
            }
            reconnectAttempts = 0;
            term.clear();
            connect();
        }

        // Handle window resize
        window.addEventListener('resize', function() {
            if (fitAddon) {
                fitAddon.fit();
            }
        });

        // Handle keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl+Shift+R to reconnect
            if (e.ctrlKey && e.shiftKey && e.key === 'R') {
                e.preventDefault();
                reconnect();
            }
        });

        // Set window title with VM ID
        document.title = 'Console: ' + vmId.substring(0, 8) + '... - FireCrackManager';

        // Initialize
        initTerminal();
        connect();
    </script>
</body>
</html>`, vmID, vmID)
}

func (wc *WebConsole) handleMigrationPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Migration", "migration", wc.renderMigrationPage(), sess))
}

func (wc *WebConsole) renderMigrationPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Migration Server</h3>
        <div>
            <span id="serverStatus" class="badge badge-secondary">Unknown</span>
        </div>
    </div>
    <div class="card-body">
        <div class="form-group">
            <label>Server Port</label>
            <div style="display: flex; gap: 10px; align-items: center;">
                <input type="number" id="serverPort" value="9090" style="width: 150px;">
                <button class="btn btn-primary" id="toggleServerBtn" onclick="toggleServer()">Start Server</button>
            </div>
        </div>
        <p class="help-text">The migration server listens for incoming VM transfers from other FireCrackManager instances.</p>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Migration Keys</h3>
        <button class="btn btn-primary" onclick="openModal('createKeyModal')">
            <span class="material-icons">key</span>
            Generate Key
        </button>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Permissions</th>
                    <th>Last Used</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="keyList">
                <tr><td colspan="5">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Migrate VM</h3>
    </div>
    <div class="card-body">
        <form id="migrateForm">
            <div class="form-group">
                <label>Select VM</label>
                <select name="vm_id" id="vmSelect" required>
                    <option value="">-- Select a VM --</option>
                </select>
            </div>
            <div class="form-group">
                <label>Remote Host</label>
                <input type="text" name="remote_host" placeholder="192.168.1.100" required>
            </div>
            <div class="form-group">
                <label>Remote Port</label>
                <input type="number" name="remote_port" value="9090" required>
            </div>
            <div class="form-group">
                <label>Migration Key</label>
                <input type="password" name="migration_key" placeholder="Enter the remote server's migration key" required>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" name="compress" checked>
                    Enable compression (gzip)
                </label>
            </div>
            <button type="submit" class="btn btn-primary" id="migrateBtn">
                <span class="material-icons">send</span>
                Start Migration
            </button>
        </form>
        <div id="migrationProgress" style="display: none; margin-top: 20px;">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill" style="width: 0%;"></div>
            </div>
            <p id="progressText">Preparing migration...</p>
        </div>
    </div>
</div>

<div id="createKeyModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Generate Migration Key</h3>
            <span class="material-icons modal-close" onclick="closeModal('createKeyModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="createKeyForm">
                <div class="form-group">
                    <label>Key Name</label>
                    <input type="text" name="name" placeholder="e.g., production-server" required>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input type="text" name="description" placeholder="Optional description">
                </div>
                <div class="form-group">
                    <label>Permissions</label>
                    <div style="display: flex; gap: 20px;">
                        <label><input type="checkbox" name="allow_push" checked> Allow receiving VMs</label>
                        <label><input type="checkbox" name="allow_pull" checked> Allow sending VMs</label>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createKeyModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createKey()">Generate</button>
        </div>
    </div>
</div>

<div id="showKeyModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Migration Key Generated</h3>
            <span class="material-icons modal-close" onclick="closeModal('showKeyModal')">close</span>
        </div>
        <div class="modal-body">
            <p><strong>Important:</strong> Copy this key now. It will not be shown again!</p>
            <div class="form-group">
                <label>Key</label>
                <div style="display: flex; gap: 10px;">
                    <input type="text" id="generatedKey" readonly style="font-family: monospace;">
                    <button class="btn btn-secondary" onclick="copyKey()">
                        <span class="material-icons">content_copy</span>
                    </button>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-primary" onclick="closeModal('showKeyModal')">Done</button>
        </div>
    </div>
</div>

<style>
.progress-bar {
    width: 100%;
    height: 20px;
    background: #333;
    border-radius: 4px;
    overflow: hidden;
}
.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #2196f3, #64b5f6);
    transition: width 0.3s ease;
}
.help-text {
    color: #888;
    font-size: 0.9em;
    margin-top: 10px;
}
</style>

<script>
let serverRunning = false;
let migrationPollInterval = null;

async function loadServerStatus() {
    const { ok, data } = await apiCall('/api/migration/server');
    if (ok) {
        serverRunning = data.running;
        updateServerUI();
        if (data.port) {
            document.getElementById('serverPort').value = data.port;
        }
    }
}

function updateServerUI() {
    const statusBadge = document.getElementById('serverStatus');
    const toggleBtn = document.getElementById('toggleServerBtn');
    const portInput = document.getElementById('serverPort');

    if (serverRunning) {
        statusBadge.textContent = 'Running';
        statusBadge.className = 'badge badge-success';
        toggleBtn.textContent = 'Stop Server';
        toggleBtn.className = 'btn btn-danger';
        portInput.disabled = true;
    } else {
        statusBadge.textContent = 'Stopped';
        statusBadge.className = 'badge badge-secondary';
        toggleBtn.textContent = 'Start Server';
        toggleBtn.className = 'btn btn-primary';
        portInput.disabled = false;
    }
}

async function toggleServer() {
    const port = parseInt(document.getElementById('serverPort').value);
    const action = serverRunning ? 'stop' : 'start';

    const { ok, data } = await apiCall('/api/migration/server', 'POST', { action, port });
    if (ok) {
        serverRunning = !serverRunning;
        updateServerUI();
    } else {
        alert(data.error || 'Failed to ' + action + ' server');
    }
}

async function loadKeys() {
    const { ok, data } = await apiCall('/api/migration/keys');
    if (!ok) return;

    const tbody = document.getElementById('keyList');
    if (!data.keys || data.keys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5">No migration keys configured</td></tr>';
        return;
    }

    tbody.innerHTML = data.keys.map(key => ` + "`" + `
        <tr>
            <td>${key.name}</td>
            <td>${key.description || '-'}</td>
            <td>
                ${key.allow_push ? '<span class="badge badge-info">Receive</span>' : ''}
                ${key.allow_pull ? '<span class="badge badge-info">Send</span>' : ''}
            </td>
            <td>${key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}</td>
            <td class="actions">
                <button class="btn btn-danger btn-sm" onclick="deleteKey('${key.id}')">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function createKey() {
    const form = document.getElementById('createKeyForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        description: formData.get('description') || '',
        allow_push: formData.get('allow_push') === 'on',
        allow_pull: formData.get('allow_pull') === 'on'
    };

    const { ok, data: resp } = await apiCall('/api/migration/keys', 'POST', data);
    if (ok) {
        closeModal('createKeyModal');
        form.reset();
        // Show the generated key
        document.getElementById('generatedKey').value = resp.key;
        openModal('showKeyModal');
        loadKeys();
    } else {
        alert(resp.error || 'Failed to create key');
    }
}

function copyKey() {
    const keyInput = document.getElementById('generatedKey');
    keyInput.select();
    document.execCommand('copy');
    alert('Key copied to clipboard');
}

async function deleteKey(keyId) {
    if (!confirm('Are you sure you want to delete this migration key?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/migration/keys/${keyId}` + "`" + `, 'DELETE');
    if (ok) {
        loadKeys();
    } else {
        alert(data.error || 'Failed to delete key');
    }
}

async function loadVMs() {
    const { ok, data } = await apiCall('/api/vms');
    if (!ok) return;

    const select = document.getElementById('vmSelect');
    select.innerHTML = '<option value="">-- Select a VM --</option>';

    if (data.vms) {
        data.vms.forEach(vm => {
            if (vm.status !== 'running') {
                const option = document.createElement('option');
                option.value = vm.id;
                option.textContent = vm.name + ' (' + vm.status + ')';
                select.appendChild(option);
            }
        });
    }
}

document.getElementById('migrateForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const formData = new FormData(this);
    const data = {
        vm_id: formData.get('vm_id'),
        remote_host: formData.get('remote_host'),
        remote_port: parseInt(formData.get('remote_port')),
        migration_key: formData.get('migration_key'),
        compress: formData.get('compress') === 'on'
    };

    if (!data.vm_id) {
        alert('Please select a VM');
        return;
    }

    document.getElementById('migrateBtn').disabled = true;
    document.getElementById('migrationProgress').style.display = 'block';
    document.getElementById('progressText').textContent = 'Starting migration...';
    document.getElementById('progressFill').style.width = '0%';

    const { ok, data: resp } = await apiCall('/api/migration/send', 'POST', data);

    if (ok) {
        // Poll for progress
        pollMigrationStatus(data.vm_id);
    } else {
        document.getElementById('migrateBtn').disabled = false;
        document.getElementById('migrationProgress').style.display = 'none';
        alert(resp.error || 'Failed to start migration');
    }
});

function pollMigrationStatus(vmId) {
    if (migrationPollInterval) {
        clearInterval(migrationPollInterval);
    }

    migrationPollInterval = setInterval(async function() {
        const { ok, data } = await apiCall('/api/migration/status?vm_id=' + vmId);

        if (!ok || !data.status) {
            return;
        }

        const progress = data.status.progress || 0;
        const bytesSent = data.status.bytes_sent || 0;
        const bytesTotal = data.status.bytes_total || 0;

        document.getElementById('progressFill').style.width = progress + '%';

        if (bytesTotal > 0) {
            const sentMB = (bytesSent / 1024 / 1024).toFixed(2);
            const totalMB = (bytesTotal / 1024 / 1024).toFixed(2);
            document.getElementById('progressText').textContent =
                'Transferring: ' + sentMB + ' MB / ' + totalMB + ' MB (' + progress.toFixed(1) + '%)';
        }

        if (data.status.state === 'completed') {
            clearInterval(migrationPollInterval);
            document.getElementById('progressText').textContent = 'Migration completed successfully!';
            document.getElementById('migrateBtn').disabled = false;
            loadVMs();
            setTimeout(function() {
                document.getElementById('migrationProgress').style.display = 'none';
            }, 3000);
        } else if (data.status.state === 'failed') {
            clearInterval(migrationPollInterval);
            document.getElementById('progressText').textContent = 'Migration failed: ' + (data.status.error || 'Unknown error');
            document.getElementById('migrateBtn').disabled = false;
        }
    }, 500);
}

// Load initial data
loadServerStatus();
loadKeys();
loadVMs();
</script>
`
}

func (wc *WebConsole) handleHostNetworkPage(w http.ResponseWriter, r *http.Request) {
	// Check if feature is enabled
	if !wc.apiServer.IsHostNetworkManagementEnabled() {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Host Network", "hostnetwork", wc.renderHostNetworkPage(), sess))
}

func (wc *WebConsole) renderHostNetworkPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Network Interfaces</h3>
        <button class="btn btn-secondary btn-sm" onclick="loadInterfaces()">
            <span class="material-icons">refresh</span> Refresh
        </button>
    </div>
    <div class="card-body">
        <div id="interfacesLoading" style="text-align: center; padding: 20px;">
            <span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>
            Loading interfaces...
        </div>
        <div id="interfacesContainer" style="display: none;">
            <table id="interfacesTable">
                <thead>
                    <tr>
                        <th>Interface</th>
                        <th>Type</th>
                        <th>State</th>
                        <th>IP Address(es)</th>
                        <th>MAC Address</th>
                        <th>MTU</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="interfacesList"></tbody>
            </table>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Default Gateway & DNS</h3>
    </div>
    <div class="card-body">
        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">Default Gateway</h4>
                <p><strong>Current:</strong> <span id="currentGateway">-</span></p>
                <p><strong>Interface:</strong> <span id="gatewayInterface">-</span></p>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">DNS Servers</h4>
                <div id="dnsServersList">Loading...</div>
                <div style="margin-top: 15px;">
                    <button class="btn btn-secondary btn-sm" onclick="openModal('dnsModal')">
                        <span class="material-icons">edit</span> Edit DNS
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Routing Table</h3>
        <div>
            <button class="btn btn-primary btn-sm" onclick="openModal('addRouteModal')">
                <span class="material-icons">add</span> Add Route
            </button>
            <button class="btn btn-secondary btn-sm" onclick="loadRoutes()">
                <span class="material-icons">refresh</span> Refresh
            </button>
        </div>
    </div>
    <div class="card-body">
        <table id="routesTable">
            <thead>
                <tr>
                    <th>Destination</th>
                    <th>Gateway</th>
                    <th>Interface</th>
                    <th>Protocol</th>
                    <th>Metric</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="routesList"></tbody>
        </table>
    </div>
</div>

<!-- Configure Interface Modal -->
<div class="modal" id="configureInterfaceModal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3>Configure Interface: <span id="configIfaceName"></span></h3>
            <button class="btn btn-secondary btn-sm" onclick="closeModal('configureInterfaceModal')">&times;</button>
        </div>
        <div class="modal-body">
            <form id="configureInterfaceForm">
                <input type="hidden" id="configIfaceNameInput">

                <div class="form-group">
                    <label>IP Addresses (CIDR format, one per line)</label>
                    <textarea id="configAddresses" rows="3" placeholder="192.168.1.10/24&#10;10.0.0.1/8" style="width: 100%; font-family: monospace;"></textarea>
                </div>

                <div class="form-group">
                    <label>Default Gateway (optional)</label>
                    <input type="text" id="configGateway" placeholder="192.168.1.1">
                </div>

                <div class="form-group">
                    <label>MTU (optional)</label>
                    <input type="number" id="configMTU" placeholder="1500">
                </div>

                <div class="form-group">
                    <label>DNS Servers (comma-separated, optional)</label>
                    <input type="text" id="configDNS" placeholder="8.8.8.8, 8.8.4.4">
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('configureInterfaceModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Apply Configuration</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Add IP Address Modal -->
<div class="modal" id="addAddressModal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h3>Add IP Address to <span id="addAddrIfaceName"></span></h3>
            <button class="btn btn-secondary btn-sm" onclick="closeModal('addAddressModal')">&times;</button>
        </div>
        <div class="modal-body">
            <form id="addAddressForm">
                <input type="hidden" id="addAddrIfaceInput">

                <div class="form-group">
                    <label>IP Address (CIDR format)</label>
                    <input type="text" id="addAddrAddress" placeholder="192.168.1.10/24" required>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('addAddressModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Address</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- DNS Modal -->
<div class="modal" id="dnsModal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h3>Configure DNS Servers</h3>
            <button class="btn btn-secondary btn-sm" onclick="closeModal('dnsModal')">&times;</button>
        </div>
        <div class="modal-body">
            <form id="dnsForm">
                <div class="form-group">
                    <label>DNS Servers (one per line)</label>
                    <textarea id="dnsServersInput" rows="4" placeholder="8.8.8.8&#10;8.8.4.4&#10;1.1.1.1" style="width: 100%; font-family: monospace;"></textarea>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('dnsModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save DNS</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Add Route Modal -->
<div class="modal" id="addRouteModal">
    <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
            <h3>Add Static Route</h3>
            <button class="btn btn-secondary btn-sm" onclick="closeModal('addRouteModal')">&times;</button>
        </div>
        <div class="modal-body">
            <form id="addRouteForm">
                <div class="form-group">
                    <label>Destination (CIDR or "default")</label>
                    <input type="text" id="routeDestination" placeholder="10.0.0.0/8 or default" required>
                </div>

                <div class="form-group">
                    <label>Gateway</label>
                    <input type="text" id="routeGateway" placeholder="192.168.1.1">
                </div>

                <div class="form-group">
                    <label>Interface (optional)</label>
                    <select id="routeInterface">
                        <option value="">Auto</option>
                    </select>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('addRouteModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Route</button>
                </div>
            </form>
        </div>
    </div>
</div>

<style>
@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
#interfacesTable, #routesTable {
    width: 100%;
    border-collapse: collapse;
}
#interfacesTable th, #interfacesTable td,
#routesTable th, #routesTable td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}
#interfacesTable th, #routesTable th {
    background: var(--bg-secondary);
    font-weight: 600;
}
.interface-type {
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 4px;
    background: var(--bg-tertiary);
}
.interface-type.physical { background: #4caf50; color: white; }
.interface-type.bridge { background: #2196f3; color: white; }
.interface-type.tap { background: #ff9800; color: white; }
.interface-type.loopback { background: #9e9e9e; color: white; }
.interface-type.veth { background: #9c27b0; color: white; }
.ip-list {
    font-family: monospace;
    font-size: 13px;
}
.ip-item {
    display: flex;
    align-items: center;
    gap: 5px;
    margin: 2px 0;
}
.ip-item button {
    padding: 2px 5px;
    font-size: 10px;
    cursor: pointer;
}
</style>

<script>
let currentInterfaces = [];

async function loadInterfaces() {
    document.getElementById('interfacesLoading').style.display = 'block';
    document.getElementById('interfacesContainer').style.display = 'none';

    const { ok, data } = await apiCall('/api/hostnet/interfaces');

    document.getElementById('interfacesLoading').style.display = 'none';
    document.getElementById('interfacesContainer').style.display = 'block';

    if (!ok) {
        document.getElementById('interfacesList').innerHTML = '<tr><td colspan="7">Failed to load interfaces</td></tr>';
        return;
    }

    currentInterfaces = data.interfaces || [];

    // Update route interface dropdown
    const routeIfaceSelect = document.getElementById('routeInterface');
    routeIfaceSelect.innerHTML = '<option value="">Auto</option>';
    currentInterfaces.forEach(iface => {
        if (!iface.is_loopback) {
            routeIfaceSelect.innerHTML += '<option value="' + iface.name + '">' + iface.name + '</option>';
        }
    });

    // Find default gateway
    let defaultGW = '-';
    let gwIface = '-';
    currentInterfaces.forEach(iface => {
        if (iface.gateway) {
            defaultGW = iface.gateway;
            gwIface = iface.name;
        }
    });
    document.getElementById('currentGateway').textContent = defaultGW;
    document.getElementById('gatewayInterface').textContent = gwIface;

    // Render interfaces table
    const tbody = document.getElementById('interfacesList');
    tbody.innerHTML = '';

    currentInterfaces.forEach(iface => {
        const row = document.createElement('tr');

        // State badge
        const stateBadge = iface.state === 'up'
            ? '<span class="badge badge-success">UP</span>'
            : '<span class="badge badge-danger">DOWN</span>';

        // Type badge
        const typeClass = iface.type || 'physical';
        const typeBadge = '<span class="interface-type ' + typeClass + '">' + (iface.type || 'physical') + '</span>';

        // IP addresses with delete buttons
        let ipHtml = '-';
        if (iface.addresses && iface.addresses.length > 0) {
            ipHtml = '<div class="ip-list">';
            iface.addresses.forEach(addr => {
                ipHtml += '<div class="ip-item">' + addr;
                if (!iface.is_loopback) {
                    ipHtml += ' <button class="btn btn-danger btn-sm" onclick="removeAddress(\'' + iface.name + '\', \'' + addr + '\')" title="Remove">&times;</button>';
                }
                ipHtml += '</div>';
            });
            ipHtml += '</div>';
        }

        // Actions
        let actions = '';
        if (!iface.is_loopback) {
            if (iface.state === 'up') {
                actions += '<button class="btn btn-warning btn-sm" onclick="setInterfaceDown(\'' + iface.name + '\')" title="Bring Down"><span class="material-icons">arrow_downward</span></button> ';
            } else {
                actions += '<button class="btn btn-success btn-sm" onclick="setInterfaceUp(\'' + iface.name + '\')" title="Bring Up"><span class="material-icons">arrow_upward</span></button> ';
            }
            actions += '<button class="btn btn-primary btn-sm" onclick="openAddAddressModal(\'' + iface.name + '\')" title="Add IP"><span class="material-icons">add</span></button> ';
            actions += '<button class="btn btn-secondary btn-sm" onclick="openConfigureModal(\'' + iface.name + '\')" title="Configure"><span class="material-icons">settings</span></button>';
        }

        row.innerHTML = '<td><strong>' + iface.name + '</strong></td>' +
            '<td>' + typeBadge + '</td>' +
            '<td>' + stateBadge + '</td>' +
            '<td>' + ipHtml + '</td>' +
            '<td><code>' + (iface.mac || '-') + '</code></td>' +
            '<td>' + (iface.mtu || '-') + '</td>' +
            '<td>' + actions + '</td>';

        tbody.appendChild(row);
    });
}

async function loadDNS() {
    const { ok, data } = await apiCall('/api/hostnet/dns');

    if (ok && data.dns_servers) {
        const dnsDiv = document.getElementById('dnsServersList');
        if (data.dns_servers.length > 0) {
            dnsDiv.innerHTML = data.dns_servers.map(s => '<div><code>' + s + '</code></div>').join('');
            document.getElementById('dnsServersInput').value = data.dns_servers.join('\n');
        } else {
            dnsDiv.innerHTML = '<em>No DNS servers configured</em>';
        }
    }
}

async function loadRoutes() {
    const { ok, data } = await apiCall('/api/hostnet/routes');

    const tbody = document.getElementById('routesList');

    if (!ok) {
        tbody.innerHTML = '<tr><td colspan="6">Failed to load routes</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    (data.routes || []).forEach(route => {
        const row = document.createElement('tr');

        // Only allow deleting static routes (not kernel routes)
        let actions = '';
        if (route.protocol !== 'kernel' && route.destination !== 'default') {
            actions = '<button class="btn btn-danger btn-sm" onclick="deleteRoute(\'' + route.destination + '\', \'' + (route.gateway || '') + '\', \'' + (route.interface || '') + '\')"><span class="material-icons">delete</span></button>';
        }

        row.innerHTML = '<td><code>' + route.destination + '</code></td>' +
            '<td>' + (route.gateway || '-') + '</td>' +
            '<td>' + (route.interface || '-') + '</td>' +
            '<td>' + (route.protocol || '-') + '</td>' +
            '<td>' + (route.metric || '-') + '</td>' +
            '<td>' + actions + '</td>';

        tbody.appendChild(row);
    });
}

async function setInterfaceUp(name) {
    const { ok, data } = await apiCall('/api/hostnet/interfaces/' + name + '/up', 'POST');
    if (ok) {
        loadInterfaces();
    } else {
        alert(data.error || 'Failed to bring interface up');
    }
}

async function setInterfaceDown(name) {
    if (!confirm('Are you sure you want to bring down ' + name + '? This may disconnect you!')) {
        return;
    }
    const { ok, data } = await apiCall('/api/hostnet/interfaces/' + name + '/down', 'POST');
    if (ok) {
        loadInterfaces();
    } else {
        alert(data.error || 'Failed to bring interface down');
    }
}

async function removeAddress(ifaceName, address) {
    if (!confirm('Remove address ' + address + ' from ' + ifaceName + '?')) {
        return;
    }
    const { ok, data } = await apiCall('/api/hostnet/interfaces/' + ifaceName + '/address', 'DELETE', { address: address });
    if (ok) {
        loadInterfaces();
    } else {
        alert(data.error || 'Failed to remove address');
    }
}

function openAddAddressModal(ifaceName) {
    document.getElementById('addAddrIfaceName').textContent = ifaceName;
    document.getElementById('addAddrIfaceInput').value = ifaceName;
    document.getElementById('addAddrAddress').value = '';
    openModal('addAddressModal');
}

document.getElementById('addAddressForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ifaceName = document.getElementById('addAddrIfaceInput').value;
    const address = document.getElementById('addAddrAddress').value;

    const { ok, data } = await apiCall('/api/hostnet/interfaces/' + ifaceName + '/address', 'POST', { address: address });
    if (ok) {
        closeModal('addAddressModal');
        loadInterfaces();
    } else {
        alert(data.error || 'Failed to add address');
    }
});

function openConfigureModal(ifaceName) {
    const iface = currentInterfaces.find(i => i.name === ifaceName);
    if (!iface) return;

    document.getElementById('configIfaceName').textContent = ifaceName;
    document.getElementById('configIfaceNameInput').value = ifaceName;
    document.getElementById('configAddresses').value = (iface.addresses || []).join('\n');
    document.getElementById('configGateway').value = iface.gateway || '';
    document.getElementById('configMTU').value = iface.mtu || '';
    document.getElementById('configDNS').value = (iface.dns_servers || []).join(', ');

    openModal('configureInterfaceModal');
}

document.getElementById('configureInterfaceForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const ifaceName = document.getElementById('configIfaceNameInput').value;
    const addresses = document.getElementById('configAddresses').value
        .split('\n')
        .map(a => a.trim())
        .filter(a => a);
    const gateway = document.getElementById('configGateway').value.trim();
    const mtu = document.getElementById('configMTU').value.trim();
    const dns = document.getElementById('configDNS').value
        .split(',')
        .map(s => s.trim())
        .filter(s => s);

    const config = {
        addresses: addresses
    };
    if (gateway) config.gateway = gateway;
    if (mtu) config.mtu = mtu;
    if (dns.length > 0) config.dns_servers = dns;

    const { ok, data } = await apiCall('/api/hostnet/interfaces/' + ifaceName, 'PUT', config);
    if (ok) {
        closeModal('configureInterfaceModal');
        loadInterfaces();
        loadDNS();
    } else {
        alert(data.error || 'Failed to configure interface');
    }
});

document.getElementById('dnsForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const servers = document.getElementById('dnsServersInput').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);

    if (servers.length === 0) {
        alert('Please enter at least one DNS server');
        return;
    }

    const { ok, data } = await apiCall('/api/hostnet/dns', 'PUT', { dns_servers: servers });
    if (ok) {
        closeModal('dnsModal');
        loadDNS();
    } else {
        alert(data.error || 'Failed to update DNS servers');
    }
});

document.getElementById('addRouteForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const destination = document.getElementById('routeDestination').value.trim();
    const gateway = document.getElementById('routeGateway').value.trim();
    const iface = document.getElementById('routeInterface').value;

    const route = { destination: destination };
    if (gateway) route.gateway = gateway;
    if (iface) route.interface = iface;

    const { ok, data } = await apiCall('/api/hostnet/routes', 'POST', route);
    if (ok) {
        closeModal('addRouteModal');
        loadRoutes();
    } else {
        alert(data.error || 'Failed to add route');
    }
});

async function deleteRoute(destination, gateway, iface) {
    if (!confirm('Delete route to ' + destination + '?')) {
        return;
    }

    let url = '/api/hostnet/routes/' + encodeURIComponent(destination);
    const params = [];
    if (gateway) params.push('gateway=' + encodeURIComponent(gateway));
    if (iface) params.push('interface=' + encodeURIComponent(iface));
    if (params.length > 0) url += '?' + params.join('&');

    const { ok, data } = await apiCall(url, 'DELETE');
    if (ok) {
        loadRoutes();
    } else {
        alert(data.error || 'Failed to delete route');
    }
}

// Load initial data
loadInterfaces();
loadDNS();
loadRoutes();
</script>
`
}

// handleVMGroupsPage serves the VM Groups management page
func (wc *WebConsole) handleVMGroupsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("VM Groups", "vmgroups", wc.renderVMGroupsPage(), sess))
}

// renderVMGroupsPage renders the VM Groups management page
func (wc *WebConsole) renderVMGroupsPage() string {
	return `
<div class="page-header">
    <h3>VM Groups</h3>
    <button class="btn btn-primary" onclick="openModal('createGroupModal')">
        <span class="material-icons">add</span> Create Group
    </button>
</div>

<div class="card">
    <div class="card-header">
        <h4>VM Groups</h4>
        <div class="search-box">
            <input type="text" id="searchGroups" placeholder="Search groups..." oninput="filterGroups()">
        </div>
    </div>
    <div class="card-body">
        <table class="data-table">
            <thead>
                <tr>
                    <th>Color</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>VMs</th>
                    <th>Permissions</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="vmGroupsTable">
                <tr><td colspan="6">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Create VM Group Modal -->
<div class="modal" id="createGroupModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create VM Group</h3>
            <button class="close-btn" onclick="closeModal('createGroupModal')">&times;</button>
        </div>
        <form id="createGroupForm" onsubmit="createVMGroup(event)">
            <div class="form-group">
                <label>Name *</label>
                <input type="text" id="groupName" required>
            </div>
            <div class="form-group">
                <label>Description</label>
                <textarea id="groupDescription" rows="2"></textarea>
            </div>
            <div class="form-group">
                <label>Color</label>
                <input type="color" id="groupColor" value="#3498db">
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal('createGroupModal')">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    </div>
</div>

<!-- Edit VM Group Modal -->
<div class="modal" id="editGroupModal">
    <div class="modal-content modal-lg">
        <div class="modal-header">
            <h3>Edit VM Group</h3>
            <button class="close-btn" onclick="closeModal('editGroupModal')">&times;</button>
        </div>
        <div class="tabs">
            <button class="tab-btn active" onclick="showTab('general')">General</button>
            <button class="tab-btn" onclick="showTab('vms')">VMs</button>
            <button class="tab-btn" onclick="showTab('permissions')">Permissions</button>
        </div>
        <div id="tab-general" class="tab-content active">
            <form id="editGroupForm" onsubmit="updateVMGroup(event)">
                <input type="hidden" id="editGroupId">
                <div class="form-group">
                    <label>Name *</label>
                    <input type="text" id="editGroupName" required>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <textarea id="editGroupDescription" rows="2"></textarea>
                </div>
                <div class="form-group">
                    <label>Color</label>
                    <input type="color" id="editGroupColor">
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-danger" onclick="deleteVMGroup()">Delete Group</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
        <div id="tab-vms" class="tab-content">
            <div class="split-view">
                <div class="split-panel">
                    <h4>Available VMs</h4>
                    <div class="list-container" id="availableVMs"></div>
                </div>
                <div class="split-panel">
                    <h4>VMs in Group</h4>
                    <div class="list-container" id="groupVMs"></div>
                </div>
            </div>
        </div>
        <div id="tab-permissions" class="tab-content">
            <div class="form-group">
                <label>Add Group Permission</label>
                <div class="inline-form">
                    <select id="permGroupSelect"></select>
                    <select id="permTypeSelect">
                        <option value="view">View</option>
                        <option value="start_stop">Start/Stop</option>
                        <option value="full">Full Control</option>
                    </select>
                    <button type="button" class="btn btn-primary" onclick="addPermission()">Add</button>
                </div>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Group</th>
                        <th>Permissions</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="permissionsTable"></tbody>
            </table>
        </div>
    </div>
</div>

<style>
.tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
.tab-btn { background: none; border: none; padding: 0.75rem 1.5rem; cursor: pointer; color: var(--text-secondary); border-bottom: 2px solid transparent; }
.tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
.tab-content { display: none; padding: 1rem 0; }
.tab-content.active { display: block; }
.split-view { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.split-panel { border: 1px solid var(--border); border-radius: 4px; padding: 1rem; }
.split-panel h4 { margin: 0 0 0.5rem 0; font-size: 0.9rem; }
.list-container { max-height: 300px; overflow-y: auto; }
.list-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; border-bottom: 1px solid var(--border); }
.list-item:last-child { border-bottom: none; }
.list-item button { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
.inline-form { display: flex; gap: 0.5rem; align-items: center; }
.inline-form select { flex: 1; }
.color-badge { width: 20px; height: 20px; border-radius: 4px; display: inline-block; }
.search-box input { padding: 0.5rem; border: 1px solid var(--border); border-radius: 4px; width: 200px; }
</style>

<script>
let vmGroups = [];
let allVMs = [];
let allUserGroups = [];
let currentGroupId = null;

async function loadVMGroups() {
    const { ok, data } = await apiCall('/api/vmgroups');
    if (ok) {
        vmGroups = data.vm_groups || [];
        renderVMGroups();
    }
}

function renderVMGroups() {
    const search = document.getElementById('searchGroups').value.toLowerCase();
    const filtered = vmGroups.filter(g =>
        g.name.toLowerCase().includes(search) ||
        (g.description && g.description.toLowerCase().includes(search))
    );

    const tbody = document.getElementById('vmGroupsTable');
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">No VM groups found</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(g => ` + "`" + `
        <tr>
            <td><span class="color-badge" style="background-color: ${g.color || '#3498db'}"></span></td>
            <td>${g.name}</td>
            <td>${g.description || '-'}</td>
            <td>${g.vm_count || 0}</td>
            <td>${g.permission_count || 0}</td>
            <td>
                <button class="btn btn-sm" onclick="editVMGroup('${g.id}')">
                    <span class="material-icons">edit</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

function filterGroups() {
    renderVMGroups();
}

async function createVMGroup(e) {
    e.preventDefault();
    const { ok, data } = await apiCall('/api/vmgroups', 'POST', {
        name: document.getElementById('groupName').value,
        description: document.getElementById('groupDescription').value,
        color: document.getElementById('groupColor').value
    });

    if (ok) {
        closeModal('createGroupModal');
        document.getElementById('createGroupForm').reset();
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to create VM group');
    }
}

async function editVMGroup(id) {
    currentGroupId = id;

    // Load group details
    const { ok, data } = await apiCall('/api/vmgroups/' + id);
    if (!ok) {
        alert(data.error || 'Failed to load VM group');
        return;
    }

    document.getElementById('editGroupId').value = data.id;
    document.getElementById('editGroupName').value = data.name;
    document.getElementById('editGroupDescription').value = data.description || '';
    document.getElementById('editGroupColor').value = data.color || '#3498db';

    // Load VMs and permissions
    loadAllVMs();
    loadGroupVMs();
    loadGroupPermissions();
    loadUserGroups();

    showTab('general');
    openModal('editGroupModal');
}

function showTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(` + "`" + `.tab-btn[onclick="showTab('${tabName}')"]` + "`" + `).classList.add('active');
    document.getElementById('tab-' + tabName).classList.add('active');
}

async function updateVMGroup(e) {
    e.preventDefault();
    const id = document.getElementById('editGroupId').value;
    const { ok, data } = await apiCall('/api/vmgroups/' + id, 'PUT', {
        name: document.getElementById('editGroupName').value,
        description: document.getElementById('editGroupDescription').value,
        color: document.getElementById('editGroupColor').value
    });

    if (ok) {
        closeModal('editGroupModal');
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to update VM group');
    }
}

async function deleteVMGroup() {
    if (!confirm('Are you sure you want to delete this VM group?')) return;

    const id = document.getElementById('editGroupId').value;
    const { ok, data } = await apiCall('/api/vmgroups/' + id, 'DELETE');

    if (ok) {
        closeModal('editGroupModal');
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to delete VM group');
    }
}

async function loadAllVMs() {
    const { ok, data } = await apiCall('/api/vms');
    if (ok) {
        allVMs = data.vms || [];
    }
}

async function loadGroupVMs() {
    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/vms');
    const groupVMIds = new Set((data.vms || []).map(v => v.id));

    // Available VMs (not in group)
    const available = allVMs.filter(v => !groupVMIds.has(v.id));
    document.getElementById('availableVMs').innerHTML = available.length === 0
        ? '<p>No available VMs</p>'
        : available.map(v => ` + "`" + `
            <div class="list-item">
                <span>${v.name}</span>
                <button class="btn btn-sm btn-primary" onclick="addVMToGroup('${v.id}')">Add</button>
            </div>
        ` + "`" + `).join('');

    // VMs in group
    const inGroup = data.vms || [];
    document.getElementById('groupVMs').innerHTML = inGroup.length === 0
        ? '<p>No VMs in group</p>'
        : inGroup.map(v => ` + "`" + `
            <div class="list-item">
                <span>${v.name}</span>
                <button class="btn btn-sm btn-danger" onclick="removeVMFromGroup('${v.id}')">Remove</button>
            </div>
        ` + "`" + `).join('');
}

async function addVMToGroup(vmId) {
    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/vms', 'POST', { vm_id: vmId });
    if (ok) {
        loadGroupVMs();
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to add VM to group');
    }
}

async function removeVMFromGroup(vmId) {
    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/vms/' + vmId, 'DELETE');
    if (ok) {
        loadGroupVMs();
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to remove VM from group');
    }
}

async function loadUserGroups() {
    const { ok, data } = await apiCall('/api/groups');
    if (ok) {
        allUserGroups = data.groups || [];
        document.getElementById('permGroupSelect').innerHTML = allUserGroups.map(g =>
            ` + "`" + `<option value="${g.id}">${g.name}</option>` + "`" + `
        ).join('');
    }
}

async function loadGroupPermissions() {
    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/permissions');
    const perms = data.permissions || [];

    document.getElementById('permissionsTable').innerHTML = perms.length === 0
        ? '<tr><td colspan="3">No permissions set</td></tr>'
        : perms.map(p => ` + "`" + `
            <tr>
                <td>${p.group_name || p.group_id}</td>
                <td>${p.permissions}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="removePermission('${p.group_id}')">Remove</button>
                </td>
            </tr>
        ` + "`" + `).join('');
}

async function addPermission() {
    const groupId = document.getElementById('permGroupSelect').value;
    const permissions = document.getElementById('permTypeSelect').value;

    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/permissions', 'POST', {
        group_id: groupId,
        permissions: permissions
    });

    if (ok) {
        loadGroupPermissions();
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to add permission');
    }
}

async function removePermission(groupId) {
    const { ok, data } = await apiCall('/api/vmgroups/' + currentGroupId + '/permissions/' + groupId, 'DELETE');
    if (ok) {
        loadGroupPermissions();
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to remove permission');
    }
}

// Load initial data
loadVMGroups();
</script>
`
}

func (wc *WebConsole) renderAccountPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">account_circle</span>My Account</h3>
        <button class="btn btn-primary" onclick="openModal('changePasswordModal')">
            <span class="material-icons">key</span> Change Password
        </button>
    </div>
    <div class="card-body">
        <div class="account-info">
            <div class="account-details">
                <table style="width: 100%; max-width: 500px;">
                    <tr>
                        <td style="width: 140px;"><strong>Username:</strong></td>
                        <td id="accountUsername">-</td>
                    </tr>
                    <tr>
                        <td><strong>Email:</strong></td>
                        <td id="accountEmail">-</td>
                    </tr>
                    <tr>
                        <td><strong>Role:</strong></td>
                        <td id="accountRole">-</td>
                    </tr>
                    <tr>
                        <td><strong>Member Since:</strong></td>
                        <td id="accountCreatedAt">-</td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">groups</span>My Groups & Privileges</h3>
    </div>
    <div class="card-body">
        <div id="adminNotice" style="display: none; background: var(--bg-secondary); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <span class="material-icons" style="color: var(--primary); vertical-align: middle;">admin_panel_settings</span>
            <span style="margin-left: 8px;">As an administrator, you have full access to all VMs and features.</span>
        </div>
        <div id="groupsList">
            <p style="color: var(--text-secondary);">Loading...</p>
        </div>
        <div id="noGroupsNotice" style="display: none; color: var(--text-secondary); font-style: italic;">
            You are not a member of any privilege groups.
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">computer</span>Accessible VMs</h3>
        <span class="badge badge-info" id="vmCount">0</span>
    </div>
    <div class="card-body">
        <div id="accessibleVMsList">
            <p style="color: var(--text-secondary);">Loading...</p>
        </div>
    </div>
</div>

<!-- Change Password Modal -->
<div id="changePasswordModal" class="modal">
    <div class="modal-content" style="max-width: 450px;">
        <div class="modal-header">
            <h2>Change Password</h2>
            <span class="material-icons modal-close" onclick="closeModal('changePasswordModal')">close</span>
        </div>
        <div class="modal-body">
            <form id="changePasswordForm" onsubmit="submitChangePassword(event)">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" id="currentPassword" required placeholder="Enter current password">
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" id="newPassword" required minlength="4" placeholder="Enter new password">
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" id="confirmPassword" required minlength="4" placeholder="Confirm new password">
                </div>
                <div class="modal-footer" style="padding: 0; margin-top: 20px;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('changePasswordModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary" id="changePasswordBtn">Change Password</button>
                </div>
            </form>
        </div>
    </div>
</div>

<style>
.account-info {
    margin-bottom: 20px;
}
.groups-container {
    display: flex;
    flex-direction: column;
    gap: 15px;
}
.group-card {
    border: 1px solid var(--border-color);
    border-radius: 8px;
    overflow: hidden;
}
.group-header {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    background: var(--bg-secondary);
    cursor: pointer;
}
.group-header:hover {
    background: #e8e8e8;
}
.group-header .material-icons {
    margin-right: 10px;
    color: var(--primary);
}
.group-header .group-name {
    font-weight: 500;
    flex: 1;
}
.group-header .toggle-icon {
    color: var(--text-secondary);
    transition: transform 0.2s;
}
.group-header.collapsed .toggle-icon {
    transform: rotate(-90deg);
}
.group-content {
    padding: 16px;
    border-top: 1px solid var(--border-color);
}
.group-content.collapsed {
    display: none;
}
.permissions-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 15px;
}
.permission-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    background: var(--bg-secondary);
    border-radius: 16px;
    font-size: 12px;
    color: var(--text-secondary);
}
.permission-badge .material-icons {
    font-size: 14px;
}
.group-vms {
    margin-top: 10px;
}
.group-vms h5 {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 8px;
}
.group-vm-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.group-vm-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    background: white;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    font-size: 13px;
}
.group-vm-item a {
    color: var(--text-primary);
    text-decoration: none;
}
.group-vm-item a:hover {
    color: var(--primary);
}
.group-vm-item .vm-status {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}
.group-vm-item .vm-status.running { background: var(--success); }
.group-vm-item .vm-status.stopped { background: var(--warning); }
.group-vm-item .vm-status.error { background: var(--danger); }

.accessible-vms-table {
    width: 100%;
}
.accessible-vms-table th {
    text-align: left;
    padding: 10px;
    background: var(--bg-secondary);
    font-weight: 500;
}
.accessible-vms-table td {
    padding: 10px;
    border-bottom: 1px solid var(--border-color);
}
.accessible-vms-table tr:hover {
    background: var(--bg-secondary);
}
</style>

<script>
const permissionIcons = {
    'start': 'play_arrow',
    'stop': 'stop',
    'console': 'terminal',
    'edit': 'edit',
    'snapshot': 'photo_camera',
    'disk': 'storage'
};

async function loadAccountData() {
    const { ok, data } = await apiCall('/api/account');
    if (!ok) {
        alert('Failed to load account data');
        return;
    }

    // Populate user info
    document.getElementById('accountUsername').textContent = data.user.username;
    document.getElementById('accountEmail').textContent = data.user.email || '-';
    document.getElementById('accountRole').innerHTML = '<span class="badge badge-' + (data.user.role === 'admin' ? 'success' : 'info') + '">' + data.user.role + '</span>';
    document.getElementById('accountCreatedAt').textContent = formatDate(data.user.created_at);

    // Show admin notice if admin
    if (data.is_admin) {
        document.getElementById('adminNotice').style.display = 'flex';
    }

    // Render groups
    const groupsList = document.getElementById('groupsList');
    const noGroupsNotice = document.getElementById('noGroupsNotice');

    if (!data.groups || data.groups.length === 0) {
        groupsList.innerHTML = '';
        if (!data.is_admin) {
            noGroupsNotice.style.display = 'block';
        }
    } else {
        noGroupsNotice.style.display = 'none';
        groupsList.innerHTML = '<div class="groups-container">' + data.groups.map(g => renderGroupCard(g)).join('') + '</div>';
    }

    // Render accessible VMs
    const vmsList = document.getElementById('accessibleVMsList');
    document.getElementById('vmCount').textContent = data.accessible_vms ? data.accessible_vms.length : 0;

    if (!data.accessible_vms || data.accessible_vms.length === 0) {
        vmsList.innerHTML = '<p style="color: var(--text-secondary); font-style: italic;">No VMs accessible.</p>';
    } else {
        vmsList.innerHTML = ` + "`" + `
            <table class="accessible-vms-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>Resources</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.accessible_vms.map(vm => ` + "`" + `
                        <tr>
                            <td>
                                <span class="material-icons" style="font-size: 16px; color: ${vm.status === 'running' ? 'var(--success)' : vm.status === 'error' ? 'var(--danger)' : 'var(--warning)'}; vertical-align: middle; margin-right: 6px;">computer</span>
                                <a href="/vms/${vm.id}">${vm.name}</a>
                            </td>
                            <td>
                                <span class="badge badge-${vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'warning'}">${vm.status}</span>
                            </td>
                            <td>${vm.ip_address || '-'}</td>
                            <td>${vm.vcpu} vCPU · ${vm.memory_mb} MB</td>
                        </tr>
                    ` + "`" + `).join('')}
                </tbody>
            </table>
        ` + "`" + `;
    }
}

function renderGroupCard(group) {
    const permissionsHtml = group.permissions_list && group.permissions_list.length > 0
        ? group.permissions_list.map(p => ` + "`" + `
            <span class="permission-badge">
                <span class="material-icons">${permissionIcons[p] || 'check'}</span>
                ${p}
            </span>
        ` + "`" + `).join('')
        : '<span style="color: var(--text-secondary); font-style: italic;">No specific permissions</span>';

    const vmsHtml = group.vms && group.vms.length > 0
        ? ` + "`" + `
            <div class="group-vms">
                <h5>VMs in this group:</h5>
                <div class="group-vm-list">
                    ${group.vms.map(vm => ` + "`" + `
                        <div class="group-vm-item">
                            <span class="material-icons" style="font-size: 16px; color: var(--text-secondary);">computer</span>
                            <a href="/vms/${vm.vm_id}">${vm.vm_name || vm.vm_id.substring(0, 8) + '...'}</a>
                        </div>
                    ` + "`" + `).join('')}
                </div>
            </div>
        ` + "`" + `
        : '<p style="color: var(--text-secondary); font-style: italic; font-size: 13px;">No VMs assigned to this group</p>';

    return ` + "`" + `
        <div class="group-card">
            <div class="group-header" onclick="toggleGroupCard(this)">
                <span class="material-icons">folder</span>
                <span class="group-name">${group.name}</span>
                <span class="material-icons toggle-icon">expand_more</span>
            </div>
            <div class="group-content">
                ${group.description ? '<p style="margin-bottom: 15px; color: var(--text-secondary);">' + group.description + '</p>' : ''}
                <div style="margin-bottom: 10px;">
                    <strong style="font-size: 13px; color: var(--text-secondary);">Permissions:</strong>
                </div>
                <div class="permissions-list">
                    ${permissionsHtml}
                </div>
                ${vmsHtml}
            </div>
        </div>
    ` + "`" + `;
}

function toggleGroupCard(header) {
    header.classList.toggle('collapsed');
    header.nextElementSibling.classList.toggle('collapsed');
}

async function submitChangePassword(e) {
    e.preventDefault();

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        alert('New passwords do not match');
        return;
    }

    if (newPassword.length < 4) {
        alert('Password must be at least 4 characters');
        return;
    }

    const btn = document.getElementById('changePasswordBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Changing...';

    const { ok, data } = await apiCall('/api/account/password', 'POST', {
        current_password: currentPassword,
        new_password: newPassword
    });

    btn.disabled = false;
    btn.innerHTML = 'Change Password';

    if (ok) {
        alert('Password changed successfully');
        closeModal('changePasswordModal');
        document.getElementById('currentPassword').value = '';
        document.getElementById('newPassword').value = '';
        document.getElementById('confirmPassword').value = '';
    } else {
        alert(data.error || 'Failed to change password');
    }
}

// Load account data on page load
loadAccountData();
</script>
`
}
