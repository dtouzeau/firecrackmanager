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
	wc.mux.HandleFunc("/appliances", wc.requireAuth(wc.handleAppliancesPage))
	wc.mux.HandleFunc("/store", wc.requireAuth(wc.handleStorePage))
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
	case "material-symbols-outlined.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(assets.MaterialSymbolsCSS))
	case "material-symbols-outlined.ttf":
		w.Header().Set("Content-Type", "font/ttf")
		w.Write(assets.MaterialSymbolsTTF)
	case "apexcharts.min.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte(ApexChartsJS))
	case "sweetalert2.min.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte(SweetAlert2JS))
	case "sweetalert2.min.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(SweetAlert2CSS))
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
	// Redirect admins to dashboard, others to VMs
	if sess.Role == "admin" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {
		http.Redirect(w, r, "/vms", http.StatusFound)
	}
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
		// Redirect admins to dashboard, others to VMs
		if sess.Role == "admin" {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		} else {
			http.Redirect(w, r, "/vms", http.StatusFound)
		}
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.renderLoginPage())
}

func (wc *WebConsole) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	// Non-admin users are redirected to VMs page
	if sess == nil || sess.Role != "admin" {
		http.Redirect(w, r, "/vms", http.StatusFound)
		return
	}
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
	fmt.Fprint(w, wc.baseTemplate("VM Details<div class=\"vm-title\" id=\"vmTitleName\"></div><div class=\"description-vm-title\" id=\"vmDescriptionTitle\"><span id=\"vmDescriptionText\"></span> <a href=\"#\" onclick=\"openEditDescriptionModal(); return false;\" class=\"edit-description-link\">Edit description...</a></div>", "vms", wc.renderVMDetailPage(vmID), sess))
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

func (wc *WebConsole) handleAppliancesPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	title := `<svg xmlns="http://www.w3.org/2000/svg" height="28" viewBox="0 -960 960 960" width="28" fill="currentColor" style="vertical-align: middle; margin-right: 10px;"><path d="M200-80q-33 0-56.5-23.5T120-160v-451q-18-11-29-28.5T80-680v-120q0-33 23.5-56.5T160-880h640q33 0 56.5 23.5T880-800v120q0 23-11 40.5T840-611v451q0 33-23.5 56.5T760-80H200Zm0-520v440h560v-440H200Zm-40-80h640v-120H160v120Zm200 280h240v-80H360v80Zm120 20Z"/></svg>Appliances<div class="title-designation">Exported VM appliances (.fcrack archives) ready for download or import on other systems.</div>`
	fmt.Fprint(w, wc.baseTemplate(title, "appliances", wc.renderAppliancesPage(), sess))
}

func (wc *WebConsole) handleStorePage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Store", "store", wc.renderStorePage(), sess))
}

func (wc *WebConsole) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, wc.baseTemplate("Logs", "logs", wc.renderLogsPage(), sess))
}

func (wc *WebConsole) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	sess := wc.getSession(r)
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
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
	userPerms := make(map[string]bool)
	if session != nil {
		username = session.Username
		userPerms = wc.db.GetUserPermissions(session.UserID, session.Role)
	}

	// Dashboard menu (only for admins)
	dashboardMenu := ""
	if isAdmin {
		dashboardMenu = `<a href="/dashboard" class="nav-item" data-page="dashboard">
                <span class="material-icons">dashboard</span>
                <span>Dashboard</span>
            </a>`
	}

	// Networks menu (only if admin or has networks permission)
	networksMenu := ""
	if userPerms["admin"] || userPerms["networks"] {
		networksMenu = `<a href="/networks" class="nav-item" data-page="networks">
                <span class="material-icons">hub</span>
                <span>Networks</span>
            </a>`
	}

	// Images menu (only if admin or has images permission)
	imagesMenu := ""
	if userPerms["admin"] || userPerms["images"] {
		imagesMenu = `<a href="/images" class="nav-item" data-page="images">
                <span class="material-icons">storage</span>
                <span>Images</span>
            </a>
            <a href="/docker" class="nav-item" data-page="docker">
                <span class="material-icons">cloud_download</span>
                <span>Docker Images</span>
            </a>`
	}

	// Host Network menu item (only for admins and if enabled in config)
	hostNetworkMenu := ""
	if isAdmin && wc.apiServer.IsHostNetworkManagementEnabled() {
		hostNetworkMenu = `<a href="/hostnetwork" class="nav-item" data-page="hostnetwork">
                <span class="material-icons">lan</span>
                <span>Host Network</span>
            </a>`
	}

	// Migration menu (only for admins)
	migrationMenu := ""
	if isAdmin {
		migrationMenu = `<a href="/migration" class="nav-item" data-page="migration">
                <span class="material-icons">swap_horiz</span>
                <span>Migration</span>
            </a>`
	}

	adminMenu := ""
	settingsMenu := ""
	if isAdmin {
		adminMenu = `<a href="/vmgroups" class="nav-item" data-page="vmgroups">
            <span class="material-icons">folder_special</span>
            <span>VM Groups</span>
        </a>
        <a href="/users" class="nav-item" data-page="users">
            <span class="material-icons">people</span>
            <span>Users & Groups</span>
        </a>`
		settingsMenu = `<a href="/settings" class="nav-item" data-page="settings">
                <span class="material-icons">settings</span>
                <span>Settings</span>
            </a>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - FireCrackManager</title>
    <link href="/assets/material-icons.css" rel="stylesheet">
    <link href="/assets/sweetalert2.min.css" rel="stylesheet">
    <style>`+MainLayoutCSS+`</style>
    <script src="/assets/sweetalert2.min.js"></script>
    <script>
        // SweetAlert2 wrapper functions - override native dialogs
        const _originalAlert = window.alert;
        const _originalConfirm = window.confirm;

        // Custom alert using SweetAlert2
        window.alert = function(message) {
            // Determine icon based on message content
            let icon = 'info';
            let title = 'Information';
            const msgLower = (message || '').toLowerCase();
            if (msgLower.includes('error') || msgLower.includes('failed') || msgLower.includes('cannot')) {
                icon = 'error';
                title = 'Error';
            } else if (msgLower.includes('success') || msgLower.includes('completed') || msgLower.includes('saved') || msgLower.includes('created') || msgLower.includes('deleted') || msgLower.includes('updated')) {
                icon = 'success';
                title = 'Success';
            } else if (msgLower.includes('warning') || msgLower.includes('please')) {
                icon = 'warning';
                title = 'Warning';
            }

            Swal.fire({
                title: title,
                text: message,
                icon: icon,
                confirmButtonText: 'OK',
                confirmButtonColor: '#1ab394',
                background: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                customClass: {
                    popup: 'swal-dark-theme'
                }
            });
        };

        // Custom confirm using SweetAlert2 - returns Promise
        // For synchronous code compatibility, we provide showConfirm() as async alternative
        window.showConfirm = async function(message, title = 'Confirm') {
            const result = await Swal.fire({
                title: title,
                text: message,
                icon: 'question',
                showCancelButton: true,
                confirmButtonText: 'Yes',
                cancelButtonText: 'Cancel',
                confirmButtonColor: '#1ab394',
                cancelButtonColor: '#6c757d',
                background: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                customClass: {
                    popup: 'swal-dark-theme'
                }
            });
            return result.isConfirmed;
        };

        // Toast notification helper
        window.showToast = function(message, icon = 'success') {
            const Toast = Swal.mixin({
                toast: true,
                position: 'top-end',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                didOpen: (toast) => {
                    toast.addEventListener('mouseenter', Swal.stopTimer);
                    toast.addEventListener('mouseleave', Swal.resumeTimer);
                }
            });
            Toast.fire({ icon: icon, title: message });
        };

        // Percent icon SVG helper - returns SVG element for percent symbol
        window.percentIcon = function(size = 14) {
            return '<svg xmlns="http://www.w3.org/2000/svg" height="' + size + '" viewBox="0 -960 960 960" width="' + size + '" fill="currentColor" style="vertical-align: middle;"><path d="M300-520q-58 0-99-41t-41-99q0-58 41-99t99-41q58 0 99 41t41 99q0 58-41 99t-99 41Zm0-80q25 0 42.5-17.5T360-660q0-25-17.5-42.5T300-720q-25 0-42.5 17.5T240-660q0 25 17.5 42.5T300-600Zm360 440q-58 0-99-41t-41-99q0-58 41-99t99-41q58 0 99 41t41 99q0 58-41 99t-99 41Zm0-80q25 0 42.5-17.5T720-300q0-25-17.5-42.5T660-360q-25 0-42.5 17.5T600-300q0 25 17.5 42.5T660-240Zm-444 80-56-56 584-584 56 56-584 584Z"/></svg>';
        };

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
            %s
            <a href="/vms" class="nav-item" data-page="vms">
                <span class="material-icons">memory</span>
                <span>Virtual Machines</span>
            </a>
            %s
            %s
            <a href="/appliances" class="nav-item" data-page="appliances">
                <span class="material-icons">inventory_2</span>
                <span>Appliances</span>
            </a>
            <a href="/store" class="nav-item" data-page="store">
                <span class="material-icons">store</span>
                <span>Store</span>
            </a>
            <a href="/logs" class="nav-item" data-page="logs">
                <span class="material-icons">article</span>
                <span>Logs</span>
            </a>
            %s
            %s
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
</html>`, title, dashboardMenu, networksMenu, imagesMenu, settingsMenu, migrationMenu, hostNetworkMenu, adminMenu, title, username, content, page)
}

func (wc *WebConsole) renderDashboard() string {
	return `
<div class="dashboard-grid">
    <!-- Virtual Machines Widget -->
    <div class="ibox" id="vmWidget">
        <div class="ibox-title">
            <h5>Virtual Machines</h5>
            <span class="label label-primary" id="vmStatusLabel">-</span>
        </div>
        <div class="ibox-content" id="vmWidgetContent">
            <h1 id="vmCount">-</h1>
            <div class="stat-percent text-success" id="vmRunning">- running <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
            <small>Total VMs</small>
        </div>
        <div class="ibox-content" id="kvmWarning" style="display: none; background: #ffebee; border-left: 4px solid #f44336; padding: 15px;">
            <div style="display: flex; align-items: center; gap: 10px; color: #c62828;">
                <span class="material-icons" style="font-size: 32px;">error</span>
                <div>
                    <strong style="font-size: 14px;">KVM device not found</strong>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #b71c1c;">(VMs will not run)</p>
                </div>
            </div>
        </div>
        <div class="ibox-footer" id="vmWidgetFooter">
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
            <h1 id="cpuPercent">-</h1>
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
            <div class="stat-percent text-success" id="memPercent">- <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
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
            <div class="stat-percent text-success" id="diskPercent">- <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span></div>
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
    width: 100%%;
    height: 12px;
    background: #e8e8e8;
    border-radius: 6px;
    overflow: hidden;
}
.disk-progress-bar {
    height: 100%%;
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

    bar.style.width = usedPercent + '%%';

    // Change color based on usage: green < 75%%, yellow 75-90%%, red > 90%%
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
        document.getElementById('cpuPercent').innerHTML = cpuPercent.toFixed(0) + percentIcon(20);
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
        document.getElementById('memPercent').innerHTML = memPct.toFixed(1) + percentIcon(14) + ' <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
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
        document.getElementById('diskPercent').innerHTML = diskPct.toFixed(1) + percentIcon(14) + ' <span class="material-icons" style="font-size: 14px; vertical-align: middle;">bolt</span>';
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

        // Check KVM availability and show warning if not available
        const kvmWarning = document.getElementById('kvmWarning');
        const vmWidgetContent = document.getElementById('vmWidgetContent');
        const vmWidgetFooter = document.getElementById('vmWidgetFooter');
        const vmWidget = document.getElementById('vmWidget');
        if (sys.kvm && !sys.kvm.available) {
            kvmWarning.style.display = 'block';
            vmWidgetContent.style.display = 'none';
            vmWidgetFooter.style.display = 'none';
            vmWidget.style.borderColor = '#f44336';
            document.getElementById('vmStatusLabel').textContent = 'Error';
            document.getElementById('vmStatusLabel').className = 'label label-danger';
        } else {
            kvmWarning.style.display = 'none';
            vmWidgetContent.style.display = 'block';
            vmWidgetFooter.style.display = 'block';
            vmWidget.style.borderColor = '';
        }
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
                <input type="text" id="vmSearchQuery" placeholder="Search VMs by name, description, IP, or MAC..." oninput="debounceSearch()">
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
            <table id="vmTable">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>vCPU</th>
                        <th>Memory</th>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>&nbsp;</th>
                        <th style="text-align: right;">Actions</th>
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
                    <label>Description (optional)</label>
                    <textarea name="description" rows="2" placeholder="Brief description of this VM"></textarea>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" value="1" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" value="512" min="128" step="128">
                </div>
                <div class="form-group" style="margin-top: 10px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" name="hotplug_enabled" id="createHotplugEnabled" onchange="toggleHotplugOptions('create')">
                        <span>Enable Memory Hotplug</span>
                    </label>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Allow dynamic memory adjustment while VM is running (requires kernel 5.16+)</small>
                </div>
                <div id="createHotplugOptions" style="display: none; padding: 10px; background: var(--surface); border-radius: 4px; margin-top: 10px;">
                    <div class="form-group">
                        <label>Max Memory (MB)</label>
                        <input type="number" name="hotplug_total_mb" id="createHotplugTotal" min="256" step="128" placeholder="2048">
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Maximum memory that can be hotplugged (must be greater than base memory)</small>
                    </div>
                    <div class="form-group">
                        <label>Block Size (MB)</label>
                        <select name="hotplug_block_mb" id="createHotplugBlock">
                            <option value="2" selected>2 MB (default)</option>
                            <option value="4">4 MB</option>
                            <option value="8">8 MB</option>
                            <option value="16">16 MB</option>
                            <option value="32">32 MB</option>
                            <option value="64">64 MB</option>
                            <option value="128">128 MB</option>
                        </select>
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Memory block granularity (power of 2, min 2MB)</small>
                    </div>
                    <div class="form-group">
                        <label>Slot Size (MB)</label>
                        <select name="hotplug_slot_mb" id="createHotplugSlot">
                            <option value="32">32 MB</option>
                            <option value="64">64 MB</option>
                            <option value="128" selected>128 MB (default)</option>
                            <option value="256">256 MB</option>
                            <option value="512">512 MB</option>
                        </select>
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Memory slot size for virtio-mem device</small>
                    </div>
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
                    <input type="text" name="kernel_args" placeholder="console=ttyS0,115200n8 reboot=k panic=1">
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
                    <label>Description (optional)</label>
                    <textarea name="description" id="editVmDescription" rows="2" placeholder="Brief description of this VM"></textarea>
                </div>
                <div class="form-group">
                    <label>vCPUs</label>
                    <input type="number" name="vcpu" id="editVmVcpu" min="1" max="8">
                </div>
                <div class="form-group">
                    <label>Memory (MB)</label>
                    <input type="number" name="memory_mb" id="editVmMemory" min="128" step="128">
                </div>
                <div class="form-group" style="margin-top: 10px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="editHotplugEnabled" onchange="toggleHotplugOptions('edit')">
                        <span>Enable Memory Hotplug</span>
                    </label>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Allow dynamic memory adjustment while VM is running (requires kernel 5.16+)</small>
                </div>
                <div id="editHotplugOptions" style="display: none; padding: 10px; background: var(--surface); border-radius: 4px; margin-top: 10px;">
                    <div class="form-group">
                        <label>Max Memory (MB)</label>
                        <input type="number" id="editHotplugTotal" min="256" step="128" placeholder="2048">
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Maximum memory that can be hotplugged (must be greater than base memory)</small>
                    </div>
                    <div class="form-group">
                        <label>Block Size (MB)</label>
                        <select id="editHotplugBlock">
                            <option value="2">2 MB (default)</option>
                            <option value="4">4 MB</option>
                            <option value="8">8 MB</option>
                            <option value="16">16 MB</option>
                            <option value="32">32 MB</option>
                            <option value="64">64 MB</option>
                            <option value="128">128 MB</option>
                        </select>
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Memory block granularity (power of 2, min 2MB)</small>
                    </div>
                    <div class="form-group">
                        <label>Slot Size (MB)</label>
                        <select id="editHotplugSlot">
                            <option value="32">32 MB</option>
                            <option value="64">64 MB</option>
                            <option value="128">128 MB (default)</option>
                            <option value="256">256 MB</option>
                            <option value="512">512 MB</option>
                        </select>
                        <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Memory slot size for virtio-mem device</small>
                    </div>
                </div>
                <div class="form-group">
                    <label>Network</label>
                    <select name="network_id" id="editVmNetwork">
                        <option value="">No network</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Kernel Arguments (optional)</label>
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0,115200n8 reboot=k panic=1">
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
                    <div id="importProgressBar" style="background: var(--primary); height: 4px; width: 0%%; transition: width 0.3s;"></div>
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
                    <span id="duplicateProgressPercent" style="color: var(--primary); font-weight: 500;">0</span>
                </div>
                <div style="background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; height: 8px;">
                    <div id="duplicateProgressBar" style="background: var(--primary); height: 100%%; width: 0%%; transition: width 0.3s ease;"></div>
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

<!-- Export VM Modal -->
<div id="exportVMModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Export VM as Appliance</h2>
            <span class="material-icons modal-close" onclick="closeModal('exportVMModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="exportVmId">
            <p style="margin-bottom: 15px; color: var(--text-secondary);">
                Export VM "<strong id="exportVmName"></strong>" as a .fcrack virtual appliance.
                The rootfs will be automatically shrunk before export.
            </p>
            <div class="form-group">
                <label>Appliance Description (optional)</label>
                <textarea id="exportVmDescription" rows="3" placeholder="Enter a description for this appliance..."></textarea>
                <small style="color: var(--text-secondary);">This description will be included in the appliance and restored with the VM.</small>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('exportVMModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="submitExportVM()"><span class="material-icons">download</span> Export</button>
        </div>
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
    // Reset cache to force full re-render after search
    vmDataCache = {};
    vmListFirstLoad = true;
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
        // Reset cache to force full re-render after search
        vmDataCache = {};
        vmListFirstLoad = true;
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
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 -960 960 960" style="vertical-align: middle; margin-right: 6px; fill: ${statusColor};"><path d="M280-332h260q37.8 0 63.9-26.61t26.1-64.5Q630-461 602.94-487T538-513h-9l-1-9q-7-48-43.26-79-36.27-31-84.62-31Q362-632 331-611.5 300-591 283-557l-3 5-6 1q-43.79 1.83-73.89 33.48Q170-485.88 170-441.86 170-396 202.08-364q32.09 32 77.92 32Zm0-60q-21.25 0-35.62-14.32Q230-420.65 230-441.82q0-21.18 14.38-35.68Q258.75-492 280-492h40q0-33.14 23.4-56.57T399.9-572q33.1 0 56.6 23.43T480-492v40h60q13 0 21.5 8.5T570-422q0 13-8.5 21.5T540-392H280Zm8 352v-60h62v-104H100q-24 0-42-18t-18-42v-436q0-24 18-42t42-18h600q24 0 42 18t18 42v436q0 24-18 42t-42 18H450v104h61v60H288Zm572-369v-451H204v-60h656q24 0 42 18t18 42v451h-60ZM100-264h600v-436H100v436Zm300-218Z"/></svg>
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
            <td style="text-align: right; vertical-align: middle;">
                <div class="action-menu" style="display: inline-block;">
                    <button class="btn btn-primary btn-sm action-menu-btn" onclick="toggleActionMenu('${vm.id}', event)">
                        <span class="material-icons">more_vert</span>
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

// Cache for VM data to enable incremental updates (avoid table blink)
let vmDataCache = {};
let vmListFirstLoad = true;

function createVMRow(vm) {
    const statusColor = getStatusColor(vm.status);
    const noNetwork = !vm.network_id;
    const rowStyle = noNetwork ? 'color: #dc3545;' : '';
    const statusBadge = vm.status === 'running' ? 'success' : (vm.status === 'error' || noNetwork) ? 'danger' : 'warning';
    return ` + "`" + `
        <tr data-vm-id="${vm.id}" style="${rowStyle}">
            <td>
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 -960 960 960" style="vertical-align: middle; margin-right: 6px; fill: ${noNetwork ? '#dc3545' : statusColor};" class="vm-status-icon"><path d="M280-332h260q37.8 0 63.9-26.61t26.1-64.5Q630-461 602.94-487T538-513h-9l-1-9q-7-48-43.26-79-36.27-31-84.62-31Q362-632 331-611.5 300-591 283-557l-3 5-6 1q-43.79 1.83-73.89 33.48Q170-485.88 170-441.86 170-396 202.08-364q32.09 32 77.92 32Zm0-60q-21.25 0-35.62-14.32Q230-420.65 230-441.82q0-21.18 14.38-35.68Q258.75-492 280-492h40q0-33.14 23.4-56.57T399.9-572q33.1 0 56.6 23.43T480-492v40h60q13 0 21.5 8.5T570-422q0 13-8.5 21.5T540-392H280Zm8 352v-60h62v-104H100q-24 0-42-18t-18-42v-436q0-24 18-42t42-18h600q24 0 42 18t18 42v436q0 24-18 42t-42 18H450v104h61v60H288Zm572-369v-451H204v-60h656q24 0 42 18t18 42v451h-60ZM100-264h600v-436H100v436Zm300-218Z"/></svg>
                <a href="/vms/${vm.id}" style="${rowStyle}">${vm.name}</a>
                ${vm.autorun ? '<span class="material-icons" style="font-size: 14px; color: var(--primary); vertical-align: middle; margin-left: 4px;" title="Autorun enabled">auto_mode</span>' : ''}
                ${noNetwork ? '<div style="font-size: 11px; color: #dc3545; margin-left: 24px; font-style: italic;">no defined network</div>' : ''}
                ${vm.description ? '<div class="vm-descriptions-row" title="' + vm.description.replace(/"/g, '&quot;') + '">' + vm.description.split(' ').slice(0, 15).join(' ') + (vm.description.split(' ').length > 15 ? '...' : '') + '</div>' : ''}
                <div id="export-progress-${vm.id}" class="export-progress" style="display: none;">
                    <div class="export-progress-text"><span class="material-icons" style="font-size: 14px; animation: spin 1s linear infinite;">sync</span> Exporting... <span class="export-percent">0%%</span></div>
                    <div class="export-progress-bar"><div class="export-progress-fill" style="width: 0%%"></div></div>
                </div>
            </td>
            <td class="vm-vcpu">${vm.vcpu}</td>
            <td class="vm-memory">${vm.memory_mb} MB</td>
            <td class="vm-status-cell">
                <span class="badge badge-${statusBadge}">
                    ${vm.status}
                </span>
            </td>
            <td class="vm-ip">${vm.ip_address || '-'}</td>
            <td id="ping-${vm.id}">
                ${vm.ip_address && vm.status === 'running'
                    ? '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite;">sync</span>'
                    : '-'}
            </td>
            <td style="text-align: right; vertical-align: middle;">
                <div class="action-menu" style="display: inline-block;">
                    <button class="btn btn-primary btn-sm action-menu-btn" onclick="toggleActionMenu('${vm.id}', event)">
                        <span class="material-icons">more_vert</span>
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
                        <button class="action-dropdown-item" onclick="openChangePasswordModal('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">key</span> Change Password
                        </button>
                        <button class="action-dropdown-item" onclick="createSnapshot('${vm.id}'); closeAllMenus();" ${vm.status !== 'running' || !vm.snapshot_type ? 'disabled' : ''}>
                            <span class="material-icons">photo_camera</span> Snapshots
                        </button>
                        <button class="action-dropdown-item" onclick="openDisksModal('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">storage</span> Disks
                        </button>
                        <button class="action-dropdown-item" onclick="openNetworksModal('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">lan</span> Networks
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item" onclick="shrinkVM('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">compress</span> Shrink
                        </button>
                        <button class="action-dropdown-item" onclick="duplicateVM('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">content_copy</span> Duplicate
                        </button>
                        <button class="action-dropdown-item" onclick="exportVM('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}', '${(vm.description || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">download</span> Export
                        </button>
                        <button class="action-dropdown-item" onclick="openMoveToGroupModal('${vm.id}', '${(vm.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'); closeAllMenus();">
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
    ` + "`" + `;
}

function updateVMRow(row, vm, oldVm) {
    // Only update cells that changed to avoid blinking
    const statusColor = getStatusColor(vm.status);

    // Update status icon color if status changed
    if (oldVm.status !== vm.status) {
        const icon = row.querySelector('.vm-status-icon');
        if (icon) icon.style.fill = statusColor;

        // Update status badge
        const statusCell = row.querySelector('.vm-status-cell');
        if (statusCell) {
            statusCell.innerHTML = ` + "`" + `<span class="badge badge-${vm.status === 'running' ? 'success' : vm.status === 'error' ? 'danger' : 'warning'}">${vm.status}</span>` + "`" + `;
        }

        // Update action buttons (start/stop)
        const dropdown = row.querySelector('.action-dropdown');
        if (dropdown) {
            const firstBtn = dropdown.querySelector('.action-dropdown-item');
            if (firstBtn) {
                if (vm.status === 'running') {
                    firstBtn.className = 'action-dropdown-item danger';
                    firstBtn.innerHTML = '<span class="material-icons">stop</span> Stop VM';
                    firstBtn.onclick = () => { stopVM(vm.id); closeAllMenus(); };
                } else {
                    firstBtn.className = 'action-dropdown-item success';
                    firstBtn.innerHTML = '<span class="material-icons">play_arrow</span> Start VM';
                    firstBtn.onclick = () => { startVM(vm.id); closeAllMenus(); };
                }
            }
            // Update disabled states
            dropdown.querySelectorAll('.action-dropdown-item').forEach(btn => {
                const text = btn.textContent.trim();
                if (text.includes('Console')) {
                    btn.disabled = vm.status !== 'running';
                } else if (text.includes('Edit') || text.includes('Change Password') || text.includes('Disks') || text.includes('Networks') || text.includes('Duplicate') || text.includes('Export') || text.includes('Delete')) {
                    btn.disabled = vm.status === 'running';
                } else if (text.includes('Snapshots')) {
                    btn.disabled = vm.status !== 'running' || !vm.snapshot_type;
                }
            });
        }

        // Update reachability cell when status changes
        const pingCell = document.getElementById('ping-' + vm.id);
        if (pingCell) {
            if (vm.status === 'running' && vm.ip_address) {
                // Show loading spinner and trigger reachability check
                pingCell.innerHTML = '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite;">sync</span>';
                checkVMReachability(vm.id, vm.ip_address);
            } else {
                // VM is not running, clear reachability status
                pingCell.innerHTML = '-';
            }
        }
    }

    // Update IP address if changed
    if (oldVm.ip_address !== vm.ip_address) {
        const ipCell = row.querySelector('.vm-ip');
        if (ipCell) ipCell.textContent = vm.ip_address || '-';
    }

    // Update vcpu if changed
    if (oldVm.vcpu !== vm.vcpu) {
        const vcpuCell = row.querySelector('.vm-vcpu');
        if (vcpuCell) vcpuCell.textContent = vm.vcpu;
    }

    // Update memory if changed
    if (oldVm.memory_mb !== vm.memory_mb) {
        const memCell = row.querySelector('.vm-memory');
        if (memCell) memCell.textContent = vm.memory_mb + ' MB';
    }
}

async function loadVMs(force = false) {
    // Skip refresh if search is active or action menu is open (unless forced)
    if (!force && (isSearchActive || openMenuVmId !== null)) {
        return;
    }

    const { ok, data } = await apiCall('/api/vms');
    if (!ok) return;

    const tbody = document.getElementById('vmList');

    // Handle empty state
    if (!data.vms || data.vms.length === 0) {
        if (Object.keys(vmDataCache).length > 0 || vmListFirstLoad) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><span class="material-icons">memory</span><p>No virtual machines</p></td></tr>';
            vmDataCache = {};
            vmListFirstLoad = false;
        }
        return;
    }

    // Build new VM map
    const newVMs = {};
    data.vms.forEach(vm => { newVMs[vm.id] = vm; });

    // First load or major change - render everything
    if (vmListFirstLoad || Object.keys(vmDataCache).length === 0) {
        tbody.innerHTML = data.vms.map(vm => createVMRow(vm)).join('');
        vmDataCache = newVMs;
        vmListFirstLoad = false;
    } else {
        // Incremental update
        const currentIds = new Set(Object.keys(newVMs));
        const cachedIds = new Set(Object.keys(vmDataCache));

        // Remove deleted VMs
        for (const id of cachedIds) {
            if (!currentIds.has(id)) {
                const row = tbody.querySelector(` + "`" + `tr[data-vm-id="${id}"]` + "`" + `);
                if (row) row.remove();
            }
        }

        // Add new VMs
        for (const id of currentIds) {
            if (!cachedIds.has(id)) {
                const temp = document.createElement('tbody');
                temp.innerHTML = createVMRow(newVMs[id]);
                tbody.appendChild(temp.firstElementChild);
            }
        }

        // Update existing VMs
        for (const id of currentIds) {
            if (cachedIds.has(id)) {
                const row = tbody.querySelector(` + "`" + `tr[data-vm-id="${id}"]` + "`" + `);
                if (row) {
                    updateVMRow(row, newVMs[id], vmDataCache[id]);
                }
            }
        }

        vmDataCache = newVMs;
    }

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
    const hotplugEnabled = document.getElementById('createHotplugEnabled').checked;
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
        data_disk_id: formData.get('data_disk_id') || '',
        hotplug_memory_enabled: hotplugEnabled,
        hotplug_memory_total_mb: hotplugEnabled ? (parseInt(formData.get('hotplug_total_mb')) || 0) : 0,
        hotplug_memory_block_mb: hotplugEnabled ? (parseInt(formData.get('hotplug_block_mb')) || 2) : 2,
        hotplug_memory_slot_mb: hotplugEnabled ? (parseInt(formData.get('hotplug_slot_mb')) || 128) : 128
    };

    const { ok, data: resp } = await apiCall('/api/vms', 'POST', data);
    if (ok) {
        closeModal('createVMModal');
        form.reset();
        document.getElementById('createHotplugOptions').style.display = 'none';
        loadVMs(true); // Force refresh to show new VM
    } else {
        alert(resp.error || 'Failed to create VM');
    }
}

function toggleHotplugOptions(prefix) {
    const checkbox = document.getElementById(prefix + 'HotplugEnabled');
    const options = document.getElementById(prefix + 'HotplugOptions');
    options.style.display = checkbox.checked ? 'block' : 'none';
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
        loadVMs(true);
    } else {
        alert(data.error || 'Failed to start VM');
    }
}

async function stopVM(id) {
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}/stop` + "`" + `, 'POST');
    if (ok) {
        loadVMs(true);
    } else {
        alert(data.error || 'Failed to stop VM');
    }
}

async function deleteVM(id) {
    if (!await showConfirm('Are you sure you want to delete this VM?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/vms/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadVMs(true);
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
    document.getElementById('editVmDescription').value = data.description || '';
    document.getElementById('editVmVcpu').value = data.vcpu;
    document.getElementById('editVmMemory').value = data.memory_mb;
    document.getElementById('editVmKernelArgs').value = data.kernel_args || '';
    document.getElementById('editVmDnsServers').value = data.dns_servers || '';
    document.getElementById('editVmSnapshotType').value = data.snapshot_type || '';
    document.getElementById('editVmAutorun').checked = data.autorun || false;

    // Populate memory hotplug fields
    document.getElementById('editHotplugEnabled').checked = data.hotplug_memory_enabled || false;
    document.getElementById('editHotplugTotal').value = data.hotplug_memory_total_mb || '';
    document.getElementById('editHotplugBlock').value = data.hotplug_memory_block_mb || 2;
    document.getElementById('editHotplugSlot').value = data.hotplug_memory_slot_mb || 128;
    document.getElementById('editHotplugOptions').style.display = data.hotplug_memory_enabled ? 'block' : 'none';

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
        description: document.getElementById('editVmDescription').value,
        vcpu: parseInt(document.getElementById('editVmVcpu').value) || 1,
        memory_mb: parseInt(document.getElementById('editVmMemory').value) || 512,
        network_id: document.getElementById('editVmNetwork').value,
        kernel_args: document.getElementById('editVmKernelArgs').value,
        dns_servers: document.getElementById('editVmDnsServers').value,
        snapshot_type: document.getElementById('editVmSnapshotType').value,
        autorun: document.getElementById('editVmAutorun').checked
    };

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}` + "`" + `, 'PUT', updateData);
    if (!ok) {
        alert(data.error || 'Failed to update VM');
        return;
    }

    // Update memory hotplug configuration
    const hotplugEnabled = document.getElementById('editHotplugEnabled').checked;
    const hotplugData = {
        enabled: hotplugEnabled,
        total_size_mb: hotplugEnabled ? (parseInt(document.getElementById('editHotplugTotal').value) || 0) : 0,
        block_size_mb: parseInt(document.getElementById('editHotplugBlock').value) || 2,
        slot_size_mb: parseInt(document.getElementById('editHotplugSlot').value) || 128
    };

    const { ok: hotplugOk, data: hotplugResp } = await apiCall(` + "`" + `/api/vms/${vmId}/memory-hotplug` + "`" + `, 'PUT', hotplugData);
    if (!hotplugOk) {
        alert(hotplugResp.error || 'Failed to update memory hotplug configuration');
        return;
    }

    closeModal('editVMModal');
    loadVMs();
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
    if (!await showConfirm('Create a snapshot of this VM? This will pause the VM briefly.')) return;

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
    if (!await showConfirm('Restore VM from this snapshot? The current VM state will be lost and replaced with the snapshot state.')) return;

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
    if (!await showConfirm('Delete this snapshot? This action cannot be undone.')) return;

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
        document.getElementById('duplicateProgressBar').style.width = percent + '%%';
        document.getElementById('duplicateProgressPercent').innerHTML = percent + percentIcon(14);
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
                document.getElementById('duplicateProgressBar').style.width = '0%%';
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
            document.getElementById('duplicateProgressBar').style.width = '0%%';
            return;
        }

        // Continue polling
        setTimeout(pollProgress, 300);
    };

    // Start polling after a small delay
    setTimeout(pollProgress, 200);
}

// Shrink VM rootfs functionality
async function shrinkVM(vmId, vmName) {
    if (!await showConfirm('Shrink rootfs for VM "' + vmName + '"?\n\nThis will minimize the disk size by removing unused space. The VM must be stopped.')) return;

    // Show loading indicator
    const btn = event.target.closest('button');
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Shrinking...';
    btn.disabled = true;

    try {
        const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/shrink` + "`" + `, 'POST');
        if (ok) {
            alert('RootFS shrunk successfully!');
            loadVMs(); // Refresh the list
        } else {
            alert(data.error || 'Failed to shrink rootfs');
        }
    } catch (e) {
        alert('Failed to shrink rootfs: ' + e.message);
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

// Export VM functionality
function exportVM(vmId, vmName, vmDescription) {
    document.getElementById('exportVmId').value = vmId;
    document.getElementById('exportVmName').textContent = vmName;
    document.getElementById('exportVmDescription').value = vmDescription || '';
    openModal('exportVMModal');
}

async function submitExportVM() {
    const vmId = document.getElementById('exportVmId').value;
    const vmName = document.getElementById('exportVmName').textContent;
    const description = document.getElementById('exportVmDescription').value.trim();

    closeModal('exportVMModal');

    // Show progress bar under VM name
    const progressDiv = document.getElementById('export-progress-' + vmId);
    if (progressDiv) {
        progressDiv.style.display = 'block';
    }

    try {
        const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/export` + "`" + `, 'POST', { description: description });
        if (ok && data.progress_key) {
            // Poll for progress
            pollExportProgress(vmId, data.progress_key, vmName);
        } else {
            if (progressDiv) progressDiv.style.display = 'none';
            alert(data.error || 'Failed to start export');
        }
    } catch (e) {
        if (progressDiv) progressDiv.style.display = 'none';
        alert('Failed to export VM: ' + e.message);
    }
}

async function pollExportProgress(vmId, progressKey, vmName) {
    const progressDiv = document.getElementById('export-progress-' + vmId);
    if (!progressDiv) return;

    const percentSpan = progressDiv.querySelector('.export-percent');
    const fillDiv = progressDiv.querySelector('.export-progress-fill');
    const textDiv = progressDiv.querySelector('.export-progress-text');

    const poll = async () => {
        try {
            const { ok, data } = await apiCall('/api/operations/' + progressKey);
            if (!ok) {
                progressDiv.style.display = 'none';
                alert('Failed to get export progress');
                return;
            }

            const percent = Math.round(data.percent || 0);
            if (percentSpan) percentSpan.textContent = percent + '%%';
            if (fillDiv) fillDiv.style.width = percent + '%%';

            // Update text based on stage
            if (textDiv && data.stage) {
                const icon = '<span class="material-icons" style="font-size: 14px; animation: spin 1s linear infinite;">sync</span>';
                textDiv.innerHTML = icon + ' ' + data.stage + ' <span class="export-percent">' + percent + '%%</span>';
            }

            if (data.status === 'completed') {
                progressDiv.style.display = 'none';
                // Trigger download
                if (data.result_name) {
                    const link = document.createElement('a');
                    link.href = data.result_name;
                    link.download = data.result_id || (vmName + '.fcrack');
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
                alert('Export completed! Download started.');
            } else if (data.status === 'error') {
                progressDiv.style.display = 'none';
                alert('Export failed: ' + (data.error || 'Unknown error'));
            } else {
                // Continue polling
                setTimeout(poll, 500);
            }
        } catch (e) {
            progressDiv.style.display = 'none';
            alert('Error polling export progress: ' + e.message);
        }
    };

    poll();
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
                progressBar.style.width = percent + '%%';
                progressText.textContent = ` + "`" + `Uploading... ${Math.round(percent)}%%` + "`" + `;
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
    if (!await showConfirm('Detach disk "' + diskName + '"? This will permanently delete the disk and all data on it.')) {
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
    if (!await showConfirm('Remove network interface eth' + ifaceIndex + '?')) {
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
                <p><strong>Available ports:</strong> <span id="vmPorts">-</span></p>
            </div>
            <div>
                <p><strong>vCPUs:</strong> <span id="vmVcpu">-</span></p>
                <p><strong>Memory:</strong> <span id="vmMemory">-</span> MB</p>
                <p id="vmHotplugRow" style="display: none;"><strong>Memory Hotplug:</strong>
                    <span id="vmHotplugStatus">-</span>
                    <button class="btn btn-info btn-xs" id="adjustMemoryBtn" onclick="openAdjustMemoryModal()" title="Adjust Memory" style="margin-left: 8px; display: none;">
                        <span class="material-icons">memory</span> Adjust
                    </button>
                </p>
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
                <p><strong>Kernel:</strong> <a href="#" id="vmKernelLink" onclick="openChangeKernelModal(); return false;" title="Click to change kernel" style="color: var(--primary); text-decoration: none;"><span id="vmKernel">-</span> <span class="material-icons" style="font-size: 14px; vertical-align: middle;">edit</span></a></p>
                <p><strong>SSH Server:</strong> <span id="vmSSHStatus">-</span>
                </p>
            </div>
            <div>
                <p><strong>Root Disk Size:</strong> <span id="vmDiskSize">-</span>
                    <button class="btn btn-info btn-xs" id="shrinkRootFSBtn" onclick="triggerShrinkRootFS()" title="Shrink Root Filesystem" style="margin-left: 8px;">
                        <span class="material-icons">compress</span>
                    </button>
                    <button class="btn btn-info btn-xs" id="expandRootFSBtn" onclick="triggerExpandRootFS()" title="Expand Root Filesystem" style="margin-left: 4px;">
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
                <h4 style="font-size: 14px; color: var(--text-secondary); margin-bottom: 10px;">CPU Usage (%%%%)</h4>
                <div id="cpuChart" style="height: 250px;"></div>
            </div>
            <div>
                <h4 style="font-size: 14px; color: var(--text-secondary); margin-bottom: 10px;">Memory Usage (%%%%)</h4>
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
    <div class="modal-content" style="width: 90%%%%; max-width: 1000px; height: 80vh;">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">article</span> VM Logs</h3>
            <span class="material-icons modal-close" onclick="closeModal('logsModal')">close</span>
        </div>
        <div class="modal-body" style="padding: 0; height: calc(100%%%% - 60px); display: flex; flex-direction: column;">
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
    document.getElementById('vmTitleName').textContent = data.name;
    document.getElementById('vmDescriptionText').textContent = data.description || '';
    window.currentVMDescription = data.description || '';
    document.getElementById('vmStatus').innerHTML = '<span class="badge badge-' +
        (data.status === 'running' ? 'success' : data.status === 'error' ? 'danger' : 'warning') +
        '">' + data.status + '</span>';
    document.getElementById('vmPid').textContent = data.pid || '-';
    document.getElementById('vmVcpu').textContent = data.vcpu;
    document.getElementById('vmMemory').textContent = data.memory_mb;
    document.getElementById('vmIp').textContent = data.ip_address || '-';
    document.getElementById('vmMac').textContent = data.mac_address || '-';
    document.getElementById('vmDns').textContent = data.dns_servers || '-';

    // Update memory hotplug status
    window.currentVMHotplugEnabled = data.hotplug_memory_enabled || false;
    window.currentVMHotplugTotalMB = data.hotplug_memory_total_mb || 0;
    window.currentVMBaseMemory = data.memory_mb || 0;
    const hotplugRow = document.getElementById('vmHotplugRow');
    const hotplugStatus = document.getElementById('vmHotplugStatus');
    const adjustBtn = document.getElementById('adjustMemoryBtn');
    if (data.hotplug_memory_enabled) {
        hotplugRow.style.display = 'block';
        if (data.status === 'running') {
            hotplugStatus.innerHTML = '<span class="badge badge-success">Active</span>';
            adjustBtn.style.display = 'inline-flex';
            // Fetch current hotplug status for running VM
            loadMemoryHotplugStatus();
        } else {
            hotplugStatus.innerHTML = '<span class="badge badge-warning">Configured</span> (Max: ' + data.hotplug_memory_total_mb + ' MB)';
            adjustBtn.style.display = 'none';
        }
    } else {
        hotplugRow.style.display = 'none';
        adjustBtn.style.display = 'none';
    }

    // Store network info for IP change feature
    window.currentVMNetworkId = data.network_id || '';
    window.currentVMIPAddress = data.ip_address || '';
    window.currentVMStatus = data.status;

    document.getElementById('startBtn').disabled = data.status === 'running';
    document.getElementById('stopBtn').disabled = data.status !== 'running';
    document.getElementById('consoleBtn').disabled = data.status !== 'running';
    document.getElementById('editBtn').disabled = data.status === 'running';

    // Check reachability and scan ports if VM is running and has an IP
    const reachableSpan = document.getElementById('vmReachable');
    const portsSpan = document.getElementById('vmPorts');
    if (data.ip_address && data.status === 'running') {
        reachableSpan.innerHTML = '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite; font-size: 16px; vertical-align: middle;">sync</span>';
        portsSpan.innerHTML = '<span class="material-icons" style="color: var(--text-secondary); animation: spin 1s linear infinite; font-size: 14px; vertical-align: middle;">sync</span> scanning...';
        checkReachability(data.ip_address);
        scanPorts(data.ip_address);
    } else {
        reachableSpan.innerHTML = '';
        portsSpan.textContent = '-';
    }

    // Populate disk information
    document.getElementById('vmOsRelease').textContent = data.os_release || '-';
    document.getElementById('vmInitSystem').textContent = data.init_system || '-';
    document.getElementById('vmDiskType').textContent = data.disk_type || '-';
    document.getElementById('vmDiskSize').textContent = data.disk_size_human || '-';
    document.getElementById('vmRootfsPath').textContent = data.rootfs_path || '-';

    // Populate kernel info
    document.getElementById('vmKernel').textContent = data.kernel_name || '-';
    window.currentVMKernelId = data.kernel_id || '';
    window.currentVMKernelName = data.kernel_name || '';

    // Populate SSH status
    const sshStatusSpan = document.getElementById('vmSSHStatus');
    if (data.ssh_installed) {
        sshStatusSpan.innerHTML = '<span class="badge badge-success">Installed</span> ' + (data.ssh_version || '');
    } else {
        sshStatusSpan.innerHTML = '<button class="btn btn-info btn-xs" onclick="installSSHServer()" title="Install OpenSSH Server"><span class="material-icons">download</span> Install SSH</button>';
    }

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

async function triggerShrinkRootFS() {
    if (!window.currentVMDetails) return;

    const vmName = window.currentVMDetails.name;
    if (!await showConfirm('Shrink rootfs for VM "' + vmName + '"?\n\nThis will minimize the disk size by removing unused space. The VM must be stopped.')) {
        return;
    }

    const btn = document.getElementById('shrinkRootFSBtn');
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>';
    btn.disabled = true;

    try {
        const { ok, data } = await apiCall('/api/vms/' + vmId + '/shrink', 'POST');
        if (ok) {
            alert('RootFS shrunk successfully!');
            loadVMDetails(); // Refresh to show new size
        } else {
            alert(data.error || 'Failed to shrink rootfs');
        }
    } catch (e) {
        alert('Failed to shrink rootfs: ' + e.message);
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

async function installSSHServer() {
    if (!window.currentVMDetails) return;

    const vmName = window.currentVMDetails.name;
    const isRunning = window.currentVMStatus === 'running';

    let confirmMsg = 'Install OpenSSH server in VM "' + vmName + '"?\n\n';
    if (isRunning) {
        confirmMsg += 'WARNING: The VM is currently running and will be stopped automatically for this operation.\n\n';
    }
    confirmMsg += 'This will:\n- Mount the rootfs\n- Install openssh-server package\n- Enable SSH service\n- Generate host keys';

    if (!await showConfirm(confirmMsg)) {
        return;
    }

    const btn = document.getElementById('installSSHBtn');
    const sshStatusSpan = document.getElementById('vmSSHStatus');
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Installing...';
    btn.disabled = true;
    sshStatusSpan.innerHTML = '<span class="badge badge-info">Installing...</span>';

    try {
        const { ok, data } = await apiCall('/api/vms/' + vmId + '/install-ssh', 'POST');
        if (ok) {
            let msg = 'OpenSSH server installed successfully!';
            if (data.was_running) {
                msg += '\n\nThe VM was stopped for installation. You can start it again to use SSH.';
            }
            alert(msg);
            loadVMDetails(); // Refresh to show SSH status
        } else {
            alert(data.error || 'Failed to install SSH server');
            sshStatusSpan.innerHTML = '<span class="badge badge-warning">Not installed</span>';
        }
    } catch (e) {
        alert('Failed to install SSH server: ' + e.message);
        sshStatusSpan.innerHTML = '<span class="badge badge-warning">Not installed</span>';
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
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

async function scanPorts(ip) {
    const portsSpan = document.getElementById('vmPorts');
    try {
        const { ok, data } = await apiCall('/api/scan-ports/' + ip);
        if (ok) {
            if (data.ports && data.ports.length > 0) {
                portsSpan.textContent = data.ports.join(', ');
            } else {
                portsSpan.textContent = 'none';
            }
        } else {
            portsSpan.textContent = 'scan failed';
        }
    } catch (e) {
        portsSpan.textContent = 'error';
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
    document.getElementById('statCpuPercent').innerHTML = cpuPercent.toFixed(1) + percentIcon(20);

    // Update Memory
    const memPercent = data.mem_percent || 0;
    const memUsed = data.mem_used_mb || 0;
    const memTotal = data.memory_mb || 0;
    document.getElementById('statMemPercent').innerHTML = memPercent.toFixed(1) + percentIcon(20);
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
        yaxis: { min: 0, max: 100, labels: { formatter: (val) => val.toFixed(0) + '%%%%' } },
        tooltip: { x: { format: 'yyyy-MM-dd HH:mm:ss' }, y: { formatter: (val) => val.toFixed(1) + '%%%%' } },
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
    if (!await showConfirm('Are you sure you want to delete this VM?')) return;
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
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0,115200n8 reboot=k panic=1">
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
    <div class="modal-content" style="width: 90%%%%; max-width: 1000px; height: 80vh;">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">terminal</span> VM Console</h3>
            <div style="display: flex; align-items: center; gap: 10px;">
                <button class="btn btn-secondary btn-sm" onclick="openConsoleInNewWindow()" title="Open in new window">
                    <span class="material-icons">open_in_new</span>
                </button>
                <span class="material-icons modal-close" onclick="closeConsole()">close</span>
            </div>
        </div>
        <div class="modal-body" style="padding: 0; height: calc(100%%%% - 60px);">
            <div id="terminal" style="width: 100%%%%; height: 100%%%%;"></div>
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

    // Open console in new browser window
    const consoleUrl = '/console/' + vmId;
    window.open(consoleUrl, 'vm_console_' + vmId, 'width=900,height=600,menubar=no,toolbar=no,location=no,status=no');
}

function openConsoleModal() {
    // Show modal (legacy function for backwards compatibility)
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
function openEditDescriptionModal() {
    document.getElementById('editDescriptionText').value = window.currentVMDescription || '';
    openModal('editDescriptionModal');
}

async function saveDescription() {
    const description = document.getElementById('editDescriptionText').value.trim();

    const { ok } = await apiCall('/api/vms/' + vmId, 'PUT', { description: description });

    if (ok) {
        window.currentVMDescription = description;
        document.getElementById('vmDescriptionText').textContent = description;
        closeModal('editDescriptionModal');
    } else {
        alert('Failed to save description');
    }
}

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

// Memory Hotplug functions
let currentHotplugStatus = null;

async function loadMemoryHotplugStatus() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/memory-hotplug');
    if (ok && data.running) {
        currentHotplugStatus = data;
        const pluggedMB = data.plugged_size_mib || 0;
        const baseMB = window.currentVMBaseMemory || 0;
        const totalMB = baseMB + pluggedMB;
        document.getElementById('vmHotplugStatus').innerHTML =
            '<span class="badge badge-success">Active</span> ' + totalMB + ' MB total (' + baseMB + ' + ' + pluggedMB + ' hotplugged)';
    }
}

async function openAdjustMemoryModal() {
    if (!window.currentVMHotplugEnabled) {
        alert('Memory hotplug is not enabled for this VM');
        return;
    }

    // Load current status
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/memory-hotplug');
    if (!ok) {
        alert(data.error || 'Failed to get memory hotplug status');
        return;
    }

    currentHotplugStatus = data;

    const baseMem = window.currentVMBaseMemory || 0;
    const totalMem = data.total_size_mib || window.currentVMHotplugTotalMB || 0;
    const pluggedMem = data.plugged_size_mib || 0;
    const requestedMem = data.requested_size_mib || 0;
    const maxHotplug = totalMem - baseMem;

    document.getElementById('adjustMemBaseMemory').textContent = baseMem + ' MiB';
    document.getElementById('adjustMemPluggedMemory').textContent = pluggedMem + ' MiB';
    document.getElementById('adjustMemMaxMemory').textContent = totalMem + ' MiB';
    document.getElementById('adjustMemTotalMemory').textContent = (baseMem + pluggedMem) + ' MiB';
    document.getElementById('adjustMemMaxLabel').textContent = '+' + maxHotplug + ' MiB';

    const slider = document.getElementById('adjustMemSlider');
    slider.min = 0;
    slider.max = maxHotplug;
    slider.step = data.block_size_mib || 128;
    slider.value = requestedMem;

    updateAdjustMemDisplay();
    openModal('adjustMemoryModal');
}

function updateAdjustMemDisplay() {
    const slider = document.getElementById('adjustMemSlider');
    const value = parseInt(slider.value) || 0;
    const baseMem = window.currentVMBaseMemory || 0;
    document.getElementById('adjustMemValue').textContent = '+' + value + ' MiB (Total: ' + (baseMem + value) + ' MiB)';
}

async function applyMemoryAdjustment() {
    const slider = document.getElementById('adjustMemSlider');
    const requestedMib = parseInt(slider.value) || 0;

    document.getElementById('adjustMemBtn').disabled = true;

    const { ok, data } = await apiCall('/api/vms/' + vmId + '/memory-hotplug', 'PATCH', {
        requested_size_mib: requestedMib
    });

    document.getElementById('adjustMemBtn').disabled = false;

    if (ok) {
        closeModal('adjustMemoryModal');
        loadVMDetails();
    } else {
        alert(data.error || 'Failed to adjust memory');
    }
}

// Change Kernel functions
async function openChangeKernelModal() {
    // Show warning if VM is running
    const warningDiv = document.getElementById('changeKernelRunningWarning');
    const changeBtn = document.getElementById('changeKernelBtn');
    if (window.currentVMStatus === 'running') {
        warningDiv.style.display = 'block';
        changeBtn.disabled = true;
    } else {
        warningDiv.style.display = 'none';
        changeBtn.disabled = false;
    }

    // Set current kernel
    document.getElementById('changeKernelCurrent').textContent = window.currentVMKernelName || '-';
    document.getElementById('changeKernelProgress').style.display = 'none';

    // Load available kernels
    const select = document.getElementById('changeKernelSelect');
    select.innerHTML = '<option value="">Loading kernels...</option>';

    openModal('changeKernelModal');

    const { ok, data } = await apiCall('/api/kernels');
    if (ok && data.kernels) {
        select.innerHTML = data.kernels.map(k =>
            `+"`"+`<option value="${k.id}" ${k.id === window.currentVMKernelId ? 'selected' : ''}>${k.name} (${k.version})${!k.virtio_support ? ' ⚠️ No virtio' : ''}</option>`+"`"+`
        ).join('');
    } else {
        select.innerHTML = '<option value="">Failed to load kernels</option>';
    }
}

async function changeVMKernel() {
    const newKernelId = document.getElementById('changeKernelSelect').value;

    if (!newKernelId) {
        alert('Please select a kernel');
        return;
    }

    if (newKernelId === window.currentVMKernelId) {
        closeModal('changeKernelModal');
        return;
    }

    // Show progress
    document.getElementById('changeKernelProgress').style.display = 'block';
    document.getElementById('changeKernelBtn').disabled = true;

    const { ok, data } = await apiCall('/api/vms/' + vmId, 'PUT', { kernel_id: newKernelId });

    if (ok) {
        closeModal('changeKernelModal');
        loadVMDetails();
    } else {
        document.getElementById('changeKernelProgress').style.display = 'none';
        document.getElementById('changeKernelBtn').disabled = false;
        alert(data.error || 'Failed to change kernel');
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
                <select id="changeIPSelect" style="width: 100%%%%;">
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

<!-- Adjust Memory Modal -->
<div id="adjustMemoryModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">memory</span> Adjust Memory (Hotplug)</h3>
            <span class="material-icons modal-close" onclick="closeModal('adjustMemoryModal')">close</span>
        </div>
        <div class="modal-body">
            <div style="background: #e3f2fd; border: 1px solid #64b5f6; border-radius: 6px; padding: 12px; margin-bottom: 15px;">
                <span class="material-icons" style="color: #1976d2; vertical-align: middle;">info</span>
                <strong style="color: #0d47a1;">Memory Hotplug Active</strong>
                <p style="margin: 5px 0 0; color: #1565c0; font-size: 13px;">Adjust the VM's memory while it's running. Changes take effect immediately.</p>
            </div>
            <div class="form-group">
                <label>Current Status</label>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 8px;">
                    <div style="background: var(--surface); padding: 10px; border-radius: 6px;">
                        <p style="margin: 0; color: var(--text-secondary); font-size: 12px;">Base Memory</p>
                        <p style="margin: 4px 0 0; font-size: 18px; font-weight: 500;" id="adjustMemBaseMemory">-</p>
                    </div>
                    <div style="background: var(--surface); padding: 10px; border-radius: 6px;">
                        <p style="margin: 0; color: var(--text-secondary); font-size: 12px;">Currently Plugged</p>
                        <p style="margin: 4px 0 0; font-size: 18px; font-weight: 500;" id="adjustMemPluggedMemory">-</p>
                    </div>
                    <div style="background: var(--surface); padding: 10px; border-radius: 6px;">
                        <p style="margin: 0; color: var(--text-secondary); font-size: 12px;">Max Available</p>
                        <p style="margin: 4px 0 0; font-size: 18px; font-weight: 500;" id="adjustMemMaxMemory">-</p>
                    </div>
                    <div style="background: var(--surface); padding: 10px; border-radius: 6px;">
                        <p style="margin: 0; color: var(--text-secondary); font-size: 12px;">Total Effective</p>
                        <p style="margin: 4px 0 0; font-size: 18px; font-weight: 500; color: var(--primary);" id="adjustMemTotalMemory">-</p>
                    </div>
                </div>
            </div>
            <div class="form-group" style="margin-top: 15px;">
                <label>New Requested Memory (MiB)</label>
                <input type="range" id="adjustMemSlider" min="0" max="1024" step="128" value="0" style="width: 100%%%%; margin-top: 8px;" oninput="updateAdjustMemDisplay()">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px;">
                    <span style="color: var(--text-secondary); font-size: 12px;">Base Only</span>
                    <span id="adjustMemValue" style="font-size: 18px; font-weight: 600; color: var(--primary);">0 MiB</span>
                    <span style="color: var(--text-secondary); font-size: 12px;" id="adjustMemMaxLabel">Max</span>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('adjustMemoryModal')">Cancel</button>
            <button type="button" class="btn btn-primary" id="adjustMemBtn" onclick="applyMemoryAdjustment()"><span class="material-icons">check</span> Apply</button>
        </div>
    </div>
</div>

<div id="editDescriptionModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">edit_note</span> Edit Description</h3>
            <span class="material-icons modal-close" onclick="closeModal('editDescriptionModal')">close</span>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label>Description</label>
                <textarea id="editDescriptionText" rows="3" placeholder="Enter a description for this VM..." style="width: 100%%%%; resize: vertical;"></textarea>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('editDescriptionModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveDescription()"><span class="material-icons">save</span> Save</button>
        </div>
    </div>
</div>

<!-- Change Kernel Modal -->
<div id="changeKernelModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3><span class="material-icons" style="vertical-align: middle;">memory</span> Change Kernel</h3>
            <span class="material-icons modal-close" onclick="closeModal('changeKernelModal')">close</span>
        </div>
        <div class="modal-body">
            <div id="changeKernelRunningWarning" style="display: none; background: #fff3e0; border: 1px solid #ffb74d; border-radius: 6px; padding: 12px; margin-bottom: 15px;">
                <span class="material-icons" style="color: #f57c00; vertical-align: middle;">warning</span>
                <strong style="color: #e65100;">VM must be stopped to change kernel.</strong>
                <p style="margin: 5px 0 0; color: #795548; font-size: 13px;">Please stop the VM first, then change the kernel and restart.</p>
            </div>
            <div class="form-group">
                <label>Current Kernel</label>
                <p id="changeKernelCurrent" style="font-size: 16px; font-weight: 500; color: var(--primary);">-</p>
            </div>
            <div class="form-group">
                <label>Select New Kernel</label>
                <select id="changeKernelSelect" style="width: 100%%%%;">
                    <option value="">Loading kernels...</option>
                </select>
            </div>
            <div id="changeKernelProgress" style="display: none; margin-top: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="material-icons" style="animation: spin 1s linear infinite;">sync</span>
                    <span>Updating kernel...</span>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('changeKernelModal')">Cancel</button>
            <button type="button" class="btn btn-primary" id="changeKernelBtn" onclick="changeVMKernel()"><span class="material-icons">save</span> Save</button>
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
    if (!await showConfirm('Delete this firewall rule?')) return;
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
    if (!await showConfirm('Are you sure you want to delete this network?')) return;
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
            <button id="convertQemuBtn" class="btn btn-secondary" onclick="openConvertQemuModal()" title="Convert Proxmox/VMware images to Firecracker rootfs">
                <span class="material-icons">transform</span>
                Convert VM Image
            </button>
        </div>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th style="width: 1%%;">&nbsp;</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Format</th>
                    <th>Size</th>
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
                        <span id="uploadProgressPercent">0</span>
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

<div id="convertQemuModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Convert VM Disk Image</h3>
            <span class="material-icons modal-close" onclick="closeQemuConvertModal()">close</span>
        </div>
        <div class="modal-body">
            <form id="convertQemuForm" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Output Name</label>
                    <input type="text" name="name" id="convertQemuName" required placeholder="my-converted-rootfs">
                </div>
                <div class="form-group">
                    <label>VM Disk Image File</label>
                    <input type="file" name="file" id="convertQemuFile" required accept=".qcow2,.vmdk,.raw,.img">
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Supported formats: QCOW2 (Proxmox), VMDK (VMware), RAW disk images</small>
                </div>
                <div id="convertQemuProgress" style="display: none; margin-top: 15px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span id="convertQemuProgressText">Converting...</span>
                        <span id="convertQemuProgressPercent">0</span>
                    </div>
                    <div style="background: var(--border); border-radius: 4px; height: 8px; overflow: hidden;">
                        <div id="convertQemuProgressBar" style="background: var(--primary); height: 100%%; width: 0%%; transition: width 0.3s;"></div>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeQemuConvertModal()" id="convertQemuCancelBtn">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="startQemuConversion()" id="convertQemuSubmitBtn">
                <span class="material-icons">transform</span> Convert
            </button>
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
                    <span id="debianBuildPercent">0</span>
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
            <td>
                ${k.name}
                ${!k.virtio_support ? '<span class="badge badge-danger" style="margin-left: 8px;" title="This kernel may not have proper virtio support. VMs using this kernel may fail to boot."><span class="material-icons" style="font-size: 12px; vertical-align: middle;">warning</span> No virtio</span>' : ''}
            </td>
            <td>${k.version}</td>
            <td>${k.architecture}</td>
            <td>${formatBytes(k.size)}</td>
            <td>${k.is_default
                ? '<span class="badge badge-success">Default</span>'
                : ` + "`" + `<span class="badge badge-secondary" style="cursor: pointer;" onclick="setDefaultKernel('${k.id}')" title="Click to set as default">Default</span>` + "`" + `}</td>
            <td class="actions">
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

        // OS/Init info for description
        let osInfo = '';
        if (r.os_release) {
            osInfo = r.os_release;
        } else if (r.init_system) {
            osInfo = r.init_system;
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
            <td><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-secondary);"><line x1="22" y1="12" x2="2" y2="12"></line><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path><line x1="6" y1="16" x2="6.01" y2="16"></line><line x1="10" y1="16" x2="10.01" y2="16"></line></svg></td>
            <td>
                ${r.name}
                ${osInfo ? '<div class="rfs-description">' + osInfo + '</div>' : ''}
            </td>
            <td>${typeBadge}</td>
            <td>${r.format}</td>
            <td>${formatBytes(r.size)}</td>
            <td style="white-space: nowrap;">${usedByHtml}</td>
            <td>
                <div class="actions">
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
    progressBar.style.width = '0%%';
    progressPercent.innerHTML = '0' + percentIcon(14);

    const formData = new FormData();
    formData.append('name', name);
    formData.append('file', file);

    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percent + '%%';
            progressPercent.innerHTML = percent + percentIcon(14);
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
                progressBar.style.width = '100%%';
                progressPercent.innerHTML = '100' + percentIcon(14);
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

let qemuConversionJobId = null;
let qemuConversionPollInterval = null;
let qemuUtilsStatus = null;

// Check qemu-utils availability on page load
async function checkQemuUtilsStatus() {
    const btn = document.getElementById('convertQemuBtn');
    if (!btn) return;

    try {
        const resp = await fetch('/api/system/qemu-utils');
        qemuUtilsStatus = await resp.json();

        if (qemuUtilsStatus.available) {
            btn.disabled = false;
            btn.title = 'Convert Proxmox/VMware images to Firecracker rootfs\\n' + qemuUtilsStatus.version;
            btn.classList.remove('btn-disabled');
        } else if (qemuUtilsStatus.can_install) {
            btn.disabled = false;
            btn.title = 'qemu-utils not installed. Click to install and convert.';
            btn.classList.remove('btn-disabled');
        } else {
            btn.disabled = true;
            btn.title = 'qemu-utils not available and cannot be installed automatically';
            btn.classList.add('btn-disabled');
            btn.style.opacity = '0.5';
            btn.style.cursor = 'not-allowed';
        }
    } catch (e) {
        console.error('Failed to check qemu-utils status:', e);
    }
}

// Called when Convert VM Image button is clicked
async function openConvertQemuModal() {
    if (!qemuUtilsStatus) {
        await checkQemuUtilsStatus();
    }

    if (qemuUtilsStatus && !qemuUtilsStatus.available) {
        if (qemuUtilsStatus.can_install) {
            if (await showConfirm('qemu-utils is not installed.\n\nWould you like to install it now?\n\nThis requires administrator privileges and may take a moment.')) {
                await installQemuUtils();
            }
            return;
        } else {
            alert('qemu-utils is not available and cannot be installed automatically.\\n\\nPlease install qemu-utils manually using your package manager.');
            return;
        }
    }

    openModal('convertQemuModal');
}

// Install qemu-utils
async function installQemuUtils() {
    const btn = document.getElementById('convertQemuBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Installing...';
    btn.disabled = true;

    try {
        const resp = await fetch('/api/system/qemu-utils/install', { method: 'POST' });
        const data = await resp.json();

        if (resp.ok) {
            alert('qemu-utils installed successfully!\\n\\n' + (data.version || ''));
            // Refresh status
            await checkQemuUtilsStatus();
            // Open the modal now
            openModal('convertQemuModal');
        } else {
            alert('Failed to install qemu-utils: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Failed to install qemu-utils: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Check qemu-utils status on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check status after a short delay to ensure DOM is ready
    setTimeout(checkQemuUtilsStatus, 500);
});

function closeQemuConvertModal() {
    if (qemuConversionPollInterval) {
        clearInterval(qemuConversionPollInterval);
        qemuConversionPollInterval = null;
    }
    closeModal('convertQemuModal');
    document.getElementById('convertQemuForm').reset();
    document.getElementById('convertQemuProgress').style.display = 'none';
    document.getElementById('convertQemuSubmitBtn').disabled = false;
    document.getElementById('convertQemuCancelBtn').disabled = false;
}

async function startQemuConversion() {
    const nameInput = document.getElementById('convertQemuName');
    const fileInput = document.getElementById('convertQemuFile');
    const progressDiv = document.getElementById('convertQemuProgress');
    const progressBar = document.getElementById('convertQemuProgressBar');
    const progressText = document.getElementById('convertQemuProgressText');
    const progressPercent = document.getElementById('convertQemuProgressPercent');
    const submitBtn = document.getElementById('convertQemuSubmitBtn');
    const cancelBtn = document.getElementById('convertQemuCancelBtn');

    const name = nameInput.value.trim();
    const file = fileInput.files[0];

    if (!name) {
        alert('Please enter an output name');
        return;
    }
    if (!file) {
        alert('Please select a VM disk image file');
        return;
    }

    // Validate file extension
    const ext = file.name.toLowerCase().split('.').pop();
    if (!['qcow2', 'vmdk', 'raw', 'img'].includes(ext)) {
        alert('Unsupported file format. Supported formats: .qcow2, .vmdk, .raw, .img');
        return;
    }

    // Show progress, disable buttons
    progressDiv.style.display = 'block';
    submitBtn.disabled = true;
    cancelBtn.disabled = true;
    progressText.textContent = 'Uploading...';
    progressBar.style.width = '0%%';
    progressPercent.innerHTML = '0' + percentIcon(14);

    const formData = new FormData();
    formData.append('name', name);
    formData.append('file', file);

    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 50); // Upload is 0-50%%
            progressBar.style.width = percent + '%%';
            progressPercent.innerHTML = percent + percentIcon(14);
            const sizeMB = (e.loaded / (1024 * 1024)).toFixed(1);
            const totalMB = (e.total / (1024 * 1024)).toFixed(1);
            progressText.textContent = 'Uploading... ' + sizeMB + ' MB / ' + totalMB + ' MB';
        }
    };

    xhr.onload = function() {
        if (xhr.status === 200) {
            const resp = JSON.parse(xhr.responseText);
            if (resp.job_id) {
                // Upload complete, start polling for conversion progress
                qemuConversionJobId = resp.job_id;
                progressText.textContent = 'Converting... Please wait';
                progressBar.style.width = '50%%';
                progressPercent.innerHTML = '50' + percentIcon(14);
                pollQemuConversionProgress();
            } else {
                progressDiv.style.display = 'none';
                submitBtn.disabled = false;
                cancelBtn.disabled = false;
                alert(resp.error || 'Failed to start conversion');
            }
        } else {
            progressDiv.style.display = 'none';
            submitBtn.disabled = false;
            cancelBtn.disabled = false;
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

    xhr.open('POST', '/api/rootfs/convert-qemu');
    xhr.send(formData);
}

function pollQemuConversionProgress() {
    const progressBar = document.getElementById('convertQemuProgressBar');
    const progressText = document.getElementById('convertQemuProgressText');
    const progressPercent = document.getElementById('convertQemuProgressPercent');
    const submitBtn = document.getElementById('convertQemuSubmitBtn');
    const cancelBtn = document.getElementById('convertQemuCancelBtn');
    const progressDiv = document.getElementById('convertQemuProgress');

    qemuConversionPollInterval = setInterval(async () => {
        try {
            const resp = await fetch('/api/registry/convert/' + qemuConversionJobId);
            const data = await resp.json();

            if (data.status === 'completed') {
                clearInterval(qemuConversionPollInterval);
                qemuConversionPollInterval = null;
                progressBar.style.width = '100%%';
                progressPercent.innerHTML = '100' + percentIcon(14);
                progressText.textContent = 'Conversion complete!';
                setTimeout(() => {
                    closeQemuConvertModal();
                    loadRootfs();
                }, 1500);
            } else if (data.status === 'failed') {
                clearInterval(qemuConversionPollInterval);
                qemuConversionPollInterval = null;
                progressDiv.style.display = 'none';
                submitBtn.disabled = false;
                cancelBtn.disabled = false;
                alert('Conversion failed: ' + (data.error || 'Unknown error'));
            } else {
                // Running - update progress
                // Map conversion progress (0-100) to 50-100 (since upload was 0-50)
                const displayPercent = 50 + Math.round(data.progress / 2);
                progressBar.style.width = displayPercent + '%%';
                progressPercent.innerHTML = displayPercent + percentIcon(14);
                progressText.textContent = data.message || 'Converting...';
            }
        } catch (e) {
            console.error('Failed to poll conversion status:', e);
        }
    }, 2000);
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
    if (!await showConfirm('Are you sure you want to delete this kernel?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/kernels/${id}` + "`" + `, 'DELETE');
    if (ok) {
        loadKernels();
    } else {
        alert(data.error || 'Failed to delete kernel');
    }
}

async function deleteRootfs(id) {
    if (!await showConfirm('Are you sure you want to delete this root filesystem?')) return;
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
    document.getElementById('debianBuildPercent').innerHTML = data.progress + percentIcon(14);
    document.getElementById('debianBuildBar').style.width = data.progress + '%%';
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
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4>Services found:</h4>
                    <button class="btn btn-secondary btn-sm" onclick="clearComposeFile()" title="Remove imported file">
                        <span class="material-icons" style="font-size: 16px;">delete</span>
                        Clear
                    </button>
                </div>
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
                        Adds a basic init process for VMs without systemd
                    </small>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="convertInstallSSH" checked style="width: auto; margin: 0;">
                        Install SSH Server
                    </label>
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px; margin-left: 24px;">
                        Installs OpenSSH server and haveged for remote access
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
                        <input type="checkbox" id="composeInstallSSH" checked style="width: auto; margin: 0;">
                        Install SSH Server
                    </label>
                    <small style="display: block; color: var(--text-secondary); margin-top: 5px; margin-left: 24px;">
                        Installs OpenSSH server and haveged for remote access
                    </small>
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
                <h4 style="margin-bottom: 15px;">Environment Variables</h4>
                <div id="composeEnvVars" class="env-vars-container">
                    <p style="color: var(--text-secondary); font-size: 12px;">No environment variables defined</p>
                </div>
                <button type="button" class="btn btn-secondary btn-sm" onclick="addComposeEnvVar()" style="margin-top: 10px;">
                    <span class="material-icons" style="font-size: 16px;">add</span> Add Variable
                </button>
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

function clearComposeFile() {
    currentComposePath = '';
    composeServices = [];
    document.getElementById('composePreview').style.display = 'none';
    document.getElementById('serviceList').innerHTML = '';
    document.getElementById('composeFile').value = '';
}

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
    document.getElementById('convertInstallSSH').checked = true;
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
    const installSSH = document.getElementById('convertInstallSSH').checked;
    const dataDiskSize = parseInt(document.getElementById('convertDataDiskSize').value) || 0;
    const vcpu = parseInt(document.getElementById('convertVCPU').value) || 1;
    const memory = parseInt(document.getElementById('convertMemory').value) || 512;
    const networkId = document.getElementById('convertNetwork').value;
    const rootPassword = document.getElementById('convertRootPassword').value;

    const body = {
        image_ref: imageRef,
        name: name,
        inject_min_init: injectMinInit,
        install_ssh: installSSH,
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
    serviceList.innerHTML = composeServices.map(svc => {
        const envCount = svc.environment ? Object.keys(svc.environment).length : 0;
        const envBadge = envCount > 0 ? ` + "`" + `<span class="service-env"><span class="env-badge">${envCount} env vars</span></span>` + "`" + ` : '';
        const svcIndex = composeServices.indexOf(svc);
        return ` + "`" + `
            <div class="service-item">
                <input type="checkbox" id="svc_${svc.name}" value="${svc.name}" checked>
                <span class="service-name">${svc.name}</span>
                <span class="service-image">${svc.image || 'build context'}</span>
                ${envBadge}
                <button class="btn btn-primary btn-sm" style="margin-left: 10px;" onclick="openComposeConvertModal(${svcIndex})">
                    Convert
                </button>
            </div>
        ` + "`" + `;
    }).join('');
}

let currentServiceEnv = {};

function openComposeConvertModal(serviceIndex) {
    const svc = composeServices[serviceIndex];
    if (!svc) return;

    document.getElementById('composeServiceName').value = svc.name;
    document.getElementById('composeServiceDisplay').value = svc.name + (svc.image ? ' (' + svc.image + ')' : '');
    document.getElementById('composeOutputName').value = '';
    document.getElementById('composeDataDiskSize').value = '0';
    document.getElementById('composeInjectInit').checked = true;
    document.getElementById('composeUseDocker').checked = false;

    // Populate environment variables
    currentServiceEnv = svc.environment ? {...svc.environment} : {};
    renderComposeEnvVars();

    openModal('convertComposeModal');
}

function renderComposeEnvVars() {
    const container = document.getElementById('composeEnvVars');
    const keys = Object.keys(currentServiceEnv);

    if (keys.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); font-size: 12px;">No environment variables defined</p>';
        return;
    }

    container.innerHTML = keys.map(key => ` + "`" + `
        <div class="env-var-row">
            <input type="text" value="${escapeHtml(key)}" placeholder="KEY" data-env-key="${escapeHtml(key)}" onchange="updateComposeEnvKey(this)">
            <input type="text" value="${escapeHtml(currentServiceEnv[key])}" placeholder="value" data-env-key="${escapeHtml(key)}" onchange="updateComposeEnvValue(this, '${escapeHtml(key)}')">
            <button type="button" class="btn-icon" onclick="removeComposeEnvVar('${escapeHtml(key)}')">
                <span class="material-icons">delete</span>
            </button>
        </div>
    ` + "`" + `).join('');
}

function addComposeEnvVar() {
    let newKey = 'NEW_VAR';
    let counter = 1;
    while (currentServiceEnv.hasOwnProperty(newKey)) {
        newKey = 'NEW_VAR_' + counter++;
    }
    currentServiceEnv[newKey] = '';
    renderComposeEnvVars();
}

function removeComposeEnvVar(key) {
    delete currentServiceEnv[key];
    renderComposeEnvVars();
}

function updateComposeEnvKey(input) {
    const oldKey = input.dataset.envKey;
    const newKey = input.value.trim();

    if (newKey && newKey !== oldKey) {
        const value = currentServiceEnv[oldKey];
        delete currentServiceEnv[oldKey];
        currentServiceEnv[newKey] = value;
        renderComposeEnvVars();
    }
}

function updateComposeEnvValue(input, key) {
    currentServiceEnv[key] = input.value;
}

async function startComposeConversion() {
    const serviceName = document.getElementById('composeServiceName').value;
    const outputName = document.getElementById('composeOutputName').value.trim();
    const injectMinInit = document.getElementById('composeInjectInit').checked;
    const installSSH = document.getElementById('composeInstallSSH').checked;
    const useDocker = document.getElementById('composeUseDocker').checked;
    const dataDiskSize = parseInt(document.getElementById('composeDataDiskSize').value) || 0;

    const body = {
        compose_path: currentComposePath,
        service_name: serviceName,
        output_name: outputName,
        inject_min_init: injectMinInit,
        install_ssh: installSSH,
        use_docker: useDocker,
        environment: currentServiceEnv
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
        if (!await showConfirm('Convert ' + selected.length + ' services? Each will create a separate rootfs.')) {
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
                <table style="width: 100%%;">
                    <tr><td><strong>Version:</strong></td><td id="fcmVersion">-</td></tr>
                    <tr><td><strong>Build Date:</strong></td><td id="fcmBuildDate">-</td></tr>
                    <tr><td><strong>Uptime:</strong></td><td id="fcmUptime">-</td></tr>
                </table>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">Firecracker</h4>
                <table style="width: 100%%;">
                    <tr>
                        <td><strong>Version:</strong></td>
                        <td>
                            <span id="fcVersion">-</span>
                            <span id="fcUpdateBadge" class="badge badge-success" style="display: none; margin-left: 8px; cursor: pointer;" onclick="upgradeFirecracker()" title="Click to upgrade">
                                <span class="material-icons" style="font-size: 14px; vertical-align: middle;">upgrade</span> Update available
                            </span>
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
                <table style="width: 100%%;">
                    <tr><td><strong>Hostname:</strong></td><td id="sysHostname">-</td></tr>
                    <tr><td><strong>OS:</strong></td><td id="sysOS">-</td></tr>
                    <tr><td><strong>Architecture:</strong></td><td id="sysArch">-</td></tr>
                    <tr><td><strong>CPUs:</strong></td><td id="sysCPU">-</td></tr>
                    <tr><td><strong>Go Version:</strong></td><td id="sysGoVersion">-</td></tr>
                </table>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">KVM</h4>
                <table style="width: 100%%;">
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
        <table style="width: 100%%; max-width: 600px;">
            <tr>
                <td><strong>Proxy Settings:</strong></td>
                <td>
                    <a href="#" onclick="openModal('proxyModal'); return false;" style="color: var(--primary); text-decoration: none;">
                        <span id="proxyStatusText">Loading...</span>
                        <span class="material-icons" style="font-size: 16px; vertical-align: middle;">edit</span>
                    </a>
                </td>
            </tr>
            <tr>
                <td><strong>Active Directory:</strong></td>
                <td>
                    <a href="#" onclick="openModal('ldapModal'); return false;" style="color: var(--primary); text-decoration: none;">
                        <span id="ldapStatusText">Loading...</span>
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

<!-- Active Directory Configuration Modal -->
<div id="ldapModal" class="modal">
    <div class="modal-content" style="max-width: 600px;">
        <div class="modal-header">
            <h2>Active Directory Configuration</h2>
            <span class="material-icons modal-close" onclick="closeModal('ldapModal')">close</span>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-secondary); margin-bottom: 20px;">
                Configure Active Directory authentication. Users can log in with their AD credentials (user@domain.tld).
            </p>
            <form id="ldapForm">
                <div class="form-group">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="ldapEnabled" name="enabled" style="width: auto; margin-right: 8px;">
                        Enable Active Directory Authentication
                    </label>
                </div>
                <div id="ldapSettings" style="display: none;">
                    <div class="grid" style="grid-template-columns: 2fr 1fr; gap: 15px;">
                        <div class="form-group">
                            <label>AD Server</label>
                            <input type="text" id="ldapServer" name="server" placeholder="ad.example.com">
                            <small style="color: var(--text-secondary);">Hostname or IP address</small>
                        </div>
                        <div class="form-group">
                            <label>Port</label>
                            <input type="number" id="ldapPort" name="port" value="389" min="1" max="65535">
                            <small style="color: var(--text-secondary);">389 or 636</small>
                        </div>
                    </div>
                    <div class="grid" style="grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                        <div class="form-group">
                            <label style="display: flex; align-items: center; gap: 5px;">
                                <input type="checkbox" id="ldapUseSSL" name="use_ssl" style="width: auto;">
                                <span>LDAPS</span>
                            </label>
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center; gap: 5px;">
                                <input type="checkbox" id="ldapUseStartTLS" name="use_starttls" style="width: auto;">
                                <span>StartTLS</span>
                            </label>
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center; gap: 5px;">
                                <input type="checkbox" id="ldapSkipVerify" name="skip_verify" style="width: auto;" checked>
                                <span>Skip Verify</span>
                            </label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Service Account</label>
                        <input type="text" id="ldapBindDN" name="bind_dn" placeholder="admin@example.com" oninput="updateLdapBaseDN()">
                        <small style="color: var(--text-secondary);">user@domain.tld format</small>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="ldapBindPassword" name="bind_password" placeholder="Leave empty to keep current">
                    </div>
                    <div class="form-group">
                        <label>Base DN</label>
                        <div id="ldapBaseDNDisplay" style="padding: 8px 12px; background: var(--bg-tertiary); border-radius: 6px; font-family: monospace; min-height: 20px; color: var(--text-secondary);">-</div>
                        <small style="color: var(--text-secondary);">Auto-derived from service account domain</small>
                    </div>
                    <div style="margin-top: 15px;">
                        <button type="button" class="btn btn-secondary btn-sm" onclick="testLDAPConnection()">
                            <span class="material-icons">network_check</span> Test Connection
                        </button>
                        <span id="ldapTestResult" style="margin-left: 10px;"></span>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('ldapModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveLDAPConfig()">
                <span class="material-icons">save</span> Save
            </button>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>Kernel Updates</h3>
        <div style="display: flex; gap: 10px; align-items: center;">
            <span id="kernelUpdateBadge" class="badge badge-success" style="display: none; cursor: pointer;" onclick="document.getElementById('availableKernelList').scrollIntoView({behavior: 'smooth'})" title="Click to view available updates">
                <span class="material-icons" style="font-size: 14px; vertical-align: middle;">download</span> Updates available
            </span>
            <button class="btn btn-secondary btn-sm" onclick="checkKernelUpdates(true)" id="kernelCheckBtn">
                <span class="material-icons">refresh</span> Check Now
            </button>
        </div>
    </div>
    <div class="card-body">
        <p style="color: var(--text-secondary); margin-bottom: 20px;">
            Firecracker-compatible Linux kernels are checked daily for updates. You can download new versions to use with your VMs.
        </p>
        <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 30px;">
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">Installed Kernels</h4>
                <div id="installedKernelList" style="max-height: 200px; overflow-y: auto;">
                    <p style="color: var(--text-secondary);">Loading...</p>
                </div>
            </div>
            <div>
                <h4 style="margin-bottom: 15px; color: var(--text-secondary);">Available for Download</h4>
                <div id="availableKernelList" style="max-height: 200px; overflow-y: auto;">
                    <p style="color: var(--text-secondary);">Click "Check Now" to fetch available versions</p>
                </div>
                <p style="font-size: 12px; color: var(--text-secondary); margin-top: 10px;">
                    <span class="material-icons" style="font-size: 14px; vertical-align: middle;">schedule</span>
                    Last checked: <span id="kernelLastChecked">never</span>
                </p>
            </div>
        </div>
    </div>
</div>

<!-- Kernel Download Modal -->
<div id="kernelDownloadModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h2>Download Kernel</h2>
            <span class="material-icons modal-close" onclick="closeModal('kernelDownloadModal')">close</span>
        </div>
        <div class="modal-body">
            <p>Downloading kernel version: <strong id="downloadKernelVersion"></strong></p>
            <div style="margin-top: 20px;">
                <div class="progress-bar" style="height: 20px; background: var(--bg-tertiary); border-radius: 10px; overflow: hidden;">
                    <div id="kernelDownloadProgress" style="width: 0%%; height: 100%%; background: var(--primary); transition: width 0.3s;"></div>
                </div>
                <p id="kernelDownloadStatus" style="margin-top: 10px; font-size: 14px; color: var(--text-secondary);">Starting download...</p>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('kernelDownloadModal')" id="kernelDownloadCloseBtn" disabled>Close</button>
        </div>
    </div>
</div>

<!-- Firecracker Upgrade Progress Modal -->
<div id="upgradeProgressModal" class="modal">
    <div class="modal-content" style="max-width: 600px;">
        <div class="modal-header">
            <h2><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">system_update</span>Firecracker Upgrade</h2>
            <span class="material-icons modal-close" onclick="closeUpgradeModal()" id="upgradeModalCloseBtn" style="display: none;">close</span>
        </div>
        <div class="modal-body">
            <div style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span id="upgradeCurrentTask">Initializing...</span>
                    <span id="upgradeStepIndicator">Step 0/5</span>
                </div>
                <div class="progress-bar" style="height: 20px; background: var(--bg-tertiary); border-radius: 10px; overflow: hidden;">
                    <div id="upgradeProgressBar" style="width: 0%%; height: 100%%; background: var(--primary); transition: width 0.3s;"></div>
                </div>
            </div>
            <div style="display: flex; gap: 20px; margin-bottom: 20px;">
                <div style="flex: 1;">
                    <label style="font-size: 12px; color: var(--text-secondary);">Current Version</label>
                    <div id="upgradeCurrentVersion" style="font-weight: bold;">-</div>
                </div>
                <div style="flex: 1;">
                    <label style="font-size: 12px; color: var(--text-secondary);">Target Version</label>
                    <div id="upgradeTargetVersion" style="font-weight: bold;">-</div>
                </div>
            </div>
            <div style="background: var(--bg-tertiary); border-radius: 8px; padding: 15px; max-height: 250px; overflow-y: auto;" id="upgradeLogsContainer">
                <div style="font-family: monospace; font-size: 13px; white-space: pre-wrap;" id="upgradeLogs"></div>
            </div>
            <div id="upgradeErrorSection" style="display: none; margin-top: 15px; padding: 10px; background: rgba(244, 67, 54, 0.1); border-radius: 8px; border-left: 3px solid #f44336;">
                <span class="material-icons" style="color: #f44336; vertical-align: middle;">error</span>
                <span id="upgradeErrorMessage" style="color: #f44336;"></span>
            </div>
            <div id="upgradeSuccessSection" style="display: none; margin-top: 15px; padding: 10px; background: rgba(76, 175, 80, 0.1); border-radius: 8px; border-left: 3px solid #4caf50;">
                <span class="material-icons" style="color: #4caf50; vertical-align: middle;">check_circle</span>
                <span style="color: #4caf50;">Upgrade completed successfully!</span>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeUpgradeModal()" id="upgradeCloseBtn" disabled>Close</button>
        </div>
    </div>
</div>

<div class="card" id="ldapGroupMappingsCard" style="display: none;">
    <div class="card-header">
        <h3>LDAP Group Mappings</h3>
        <button class="btn btn-primary btn-sm" onclick="openModal('ldapGroupSearchModal')">
            <span class="material-icons">add</span> Add Mapping
        </button>
    </div>
    <div class="card-body">
        <p style="color: var(--text-secondary); margin-bottom: 20px;">
            Map Active Directory groups to local roles. Users will be assigned the role based on their AD group membership.
        </p>
        <table id="ldapMappingsTable" style="width: 100%%;">
            <thead>
                <tr>
                    <th>AD Group</th>
                    <th>Local Role</th>
                    <th>Local Group</th>
                    <th style="width: 100px;">Actions</th>
                </tr>
            </thead>
            <tbody id="ldapMappingsList">
                <tr><td colspan="4" style="text-align: center;">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- LDAP Group Search Modal -->
<div id="ldapGroupSearchModal" class="modal">
    <div class="modal-content" style="max-width: 700px;">
        <div class="modal-header">
            <h2>Add LDAP Group Mapping</h2>
            <span class="material-icons modal-close" onclick="closeModal('ldapGroupSearchModal')">close</span>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label>Search AD Groups</label>
                <div style="display: flex; gap: 10px;">
                    <input type="text" id="ldapGroupSearch" placeholder="Enter group name to search...">
                    <button type="button" class="btn btn-primary" onclick="searchLDAPGroups()">
                        <span class="material-icons">search</span> Search
                    </button>
                </div>
            </div>
            <div id="ldapGroupSearchResults" style="max-height: 300px; overflow-y: auto; margin: 15px 0; border: 1px solid var(--border-color); border-radius: 8px;">
                <p style="padding: 20px; text-align: center; color: var(--text-secondary);">Enter a search term to find AD groups</p>
            </div>
            <div id="ldapGroupMappingForm" style="display: none; border-top: 1px solid var(--border-color); padding-top: 15px;">
                <h4 style="margin-bottom: 15px;">Configure Mapping</h4>
                <input type="hidden" id="selectedGroupDN">
                <div class="form-group">
                    <label>Selected Group</label>
                    <input type="text" id="selectedGroupName" disabled>
                </div>
                <div class="form-group">
                    <label>Local Role</label>
                    <select id="ldapMappingRole" onchange="toggleLocalGroupSelect()">
                        <option value="admin">Admin (full access)</option>
                        <option value="user">User (basic access)</option>
                        <option value="group">Group-based (assign to local group)</option>
                    </select>
                </div>
                <div class="form-group" id="localGroupSelectDiv" style="display: none;">
                    <label>Assign to Local Group</label>
                    <select id="ldapMappingLocalGroup">
                        <option value="">Loading groups...</option>
                    </select>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('ldapGroupSearchModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveLDAPGroupMapping()" id="saveLDAPMappingBtn" disabled>
                <span class="material-icons">save</span> Save Mapping
            </button>
        </div>
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

if (document.getElementById('jailerEnabled')) {
    document.getElementById('jailerEnabled').addEventListener('change', function() {
        document.getElementById('jailerSettings').style.display = this.checked ? 'block' : 'none';
    });
}

if (document.getElementById('jailerForm')) {
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
}

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
        document.getElementById('fcUpdateBadge').style.display = 'none';
        document.getElementById('upgradeSection').style.display = 'none';
    }
}

let upgradePollingInterval = null;

async function upgradeFirecracker() {
    if (!await showConfirm('Are you sure you want to upgrade Firecracker? All VMs must be stopped.')) {
        return;
    }

    const btn = document.getElementById('upgradeBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Upgrading...';

    // Reset modal state
    document.getElementById('upgradeCurrentTask').textContent = 'Initializing...';
    document.getElementById('upgradeStepIndicator').textContent = 'Step 0/5';
    document.getElementById('upgradeProgressBar').style.width = '0%%';
    document.getElementById('upgradeCurrentVersion').textContent = '-';
    document.getElementById('upgradeTargetVersion').textContent = '-';
    document.getElementById('upgradeLogs').textContent = '';
    document.getElementById('upgradeErrorSection').style.display = 'none';
    document.getElementById('upgradeSuccessSection').style.display = 'none';
    document.getElementById('upgradeCloseBtn').disabled = true;
    document.getElementById('upgradeModalCloseBtn').style.display = 'none';

    // Show the modal
    openModal('upgradeProgressModal');

    const { ok, data } = await apiCall('/api/system/firecracker/upgrade', 'POST');
    if (ok) {
        // Start polling for progress
        startUpgradePolling();
    } else {
        document.getElementById('upgradeCurrentTask').textContent = 'Upgrade failed';
        document.getElementById('upgradeStepIndicator').textContent = '';
        document.getElementById('upgradeProgressBar').style.width = '100%%';
        document.getElementById('upgradeProgressBar').style.background = '#f44336';
        document.getElementById('upgradeErrorSection').style.display = 'block';
        document.getElementById('upgradeErrorMessage').textContent = data.error || 'Failed to upgrade Firecracker';
        document.getElementById('upgradeCloseBtn').disabled = false;
        document.getElementById('upgradeModalCloseBtn').style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<span class="material-icons">system_update</span> Upgrade Firecracker';
    }
}

function startUpgradePolling() {
    if (upgradePollingInterval) {
        clearInterval(upgradePollingInterval);
    }

    upgradePollingInterval = setInterval(async () => {
        const { ok, data } = await apiCall('/api/system/firecracker/upgrade/progress');
        if (ok) {
            updateUpgradeProgress(data);

            // Stop polling if completed or error
            if (data.status === 'completed' || data.status === 'error' || data.status === 'idle') {
                clearInterval(upgradePollingInterval);
                upgradePollingInterval = null;
            }
        }
    }, 500);
}

function updateUpgradeProgress(data) {
    const progressPercent = (data.step / data.total_steps) * 100;
    document.getElementById('upgradeProgressBar').style.width = progressPercent + '%%';
    document.getElementById('upgradeStepIndicator').textContent = 'Step ' + data.step + '/' + data.total_steps;
    document.getElementById('upgradeCurrentTask').textContent = data.current_task || 'Processing...';

    if (data.current_version) {
        document.getElementById('upgradeCurrentVersion').textContent = data.current_version;
    }
    if (data.target_version) {
        document.getElementById('upgradeTargetVersion').textContent = data.target_version;
    }

    // Update logs
    if (data.logs && data.logs.length > 0) {
        const logsContainer = document.getElementById('upgradeLogs');
        logsContainer.textContent = data.logs.join('\\n');
        // Auto-scroll to bottom
        document.getElementById('upgradeLogsContainer').scrollTop = document.getElementById('upgradeLogsContainer').scrollHeight;
    }

    // Handle completion states
    if (data.status === 'completed') {
        document.getElementById('upgradeSuccessSection').style.display = 'block';
        document.getElementById('upgradeCloseBtn').disabled = false;
        document.getElementById('upgradeModalCloseBtn').style.display = 'block';
        document.getElementById('upgradeProgressBar').style.background = '#4caf50';

        // Reset upgrade button
        const btn = document.getElementById('upgradeBtn');
        btn.disabled = false;
        btn.innerHTML = '<span class="material-icons">system_update</span> Upgrade Firecracker';

        // Refresh system info
        loadSystemStatus();
        checkFirecrackerUpdate();
    } else if (data.status === 'error') {
        document.getElementById('upgradeErrorSection').style.display = 'block';
        document.getElementById('upgradeErrorMessage').textContent = data.error || 'An error occurred during upgrade';
        document.getElementById('upgradeCloseBtn').disabled = false;
        document.getElementById('upgradeModalCloseBtn').style.display = 'block';
        document.getElementById('upgradeProgressBar').style.background = '#f44336';

        // Reset upgrade button
        const btn = document.getElementById('upgradeBtn');
        btn.disabled = false;
        btn.innerHTML = '<span class="material-icons">system_update</span> Upgrade Firecracker';
    }
}

function closeUpgradeModal() {
    closeModal('upgradeProgressModal');
    if (upgradePollingInterval) {
        clearInterval(upgradePollingInterval);
        upgradePollingInterval = null;
    }
    // Reset progress bar color
    document.getElementById('upgradeProgressBar').style.background = 'var(--primary)';
}

if (document.getElementById('passwordForm')) {
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
}

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

if (document.getElementById('proxyEnabled')) {
    document.getElementById('proxyEnabled').addEventListener('change', function() {
        document.getElementById('proxySettings').style.display = this.checked ? 'block' : 'none';
    });
}

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

// Kernel update functions
let installedKernelVersions = [];

async function loadInstalledKernels() {
    const listDiv = document.getElementById('installedKernelList');
    const { ok, data } = await apiCall('/api/kernels');
    if (ok && data.kernels && data.kernels.length > 0) {
        installedKernelVersions = data.kernels.map(k => {
            // Extract version from filename like "vmlinux-5.10" or "vmlinux-5.10-firecracker"
            const match = k.name.match(/vmlinux[_-]?(\d+\.\d+)/);
            return match ? match[1] : null;
        }).filter(v => v !== null);

        let html = '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        data.kernels.forEach(k => {
            html += '<span class="badge badge-primary" style="font-size: 13px;">' + k.name + '</span>';
        });
        html += '</div>';
        listDiv.innerHTML = html;
    } else {
        listDiv.innerHTML = '<p style="color: var(--text-secondary);">No kernels installed</p>';
        installedKernelVersions = [];
    }
}

async function checkKernelUpdates(forceRefresh = false) {
    const btn = document.getElementById('kernelCheckBtn');
    const listDiv = document.getElementById('availableKernelList');
    const badge = document.getElementById('kernelUpdateBadge');
    const lastCheckedSpan = document.getElementById('kernelLastChecked');

    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons">hourglass_empty</span> Checking...';

    const method = forceRefresh ? 'POST' : 'GET';
    const { ok, data } = await apiCall('/api/system/kernels/check', method);

    btn.disabled = false;
    btn.innerHTML = '<span class="material-icons">refresh</span> Check Now';

    if (ok) {
        // Update last checked time
        if (data.checked_at) {
            const checkedAt = new Date(data.checked_at);
            if (checkedAt.getTime() > 0) {
                lastCheckedSpan.textContent = checkedAt.toLocaleString();
            } else {
                lastCheckedSpan.textContent = 'never';
            }
        }

        // Show available versions
        if (data.available_kernels && data.available_kernels.length > 0) {
            let hasNewVersions = false;
            let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';
            data.available_kernels.forEach(kernel => {
                const v = kernel.version;
                const isInstalled = installedKernelVersions.includes(v);
                if (isInstalled) {
                    html += '<div style="display: flex; align-items: center; gap: 10px;">';
                    html += '<span class="badge badge-secondary" style="font-size: 13px;">v' + v + '</span>';
                    html += '<span style="color: var(--success); font-size: 12px;">Installed</span>';
                    html += '</div>';
                } else {
                    hasNewVersions = true;
                    html += '<div style="display: flex; align-items: center; gap: 10px;">';
                    html += '<span class="badge badge-success" style="font-size: 13px;">v' + v + '</span>';
                    html += '<button class="btn btn-primary btn-sm" onclick="downloadKernel(\'' + v + '\')">';
                    html += '<span class="material-icons">download</span> Download';
                    html += '</button>';
                    html += '</div>';
                }
            });
            html += '</div>';
            listDiv.innerHTML = html;

            // Show/hide update badge
            if (hasNewVersions) {
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        } else {
            listDiv.innerHTML = '<p style="color: var(--text-secondary);">No versions found. Try checking again.</p>';
            badge.style.display = 'none';
        }
    } else {
        listDiv.innerHTML = '<p style="color: var(--danger);">Failed to check: ' + (data.error || 'Unknown error') + '</p>';
        badge.style.display = 'none';
    }
}

let kernelDownloadPollInterval = null;

async function downloadKernel(version) {
    const modal = document.getElementById('kernelDownloadModal');
    const versionSpan = document.getElementById('downloadKernelVersion');
    const progressBar = document.getElementById('kernelDownloadProgress');
    const statusP = document.getElementById('kernelDownloadStatus');
    const closeBtn = document.getElementById('kernelDownloadCloseBtn');

    versionSpan.textContent = version;
    progressBar.style.width = '0%%';
    statusP.textContent = 'Starting download...';
    closeBtn.disabled = true;

    openModal('kernelDownloadModal');

    const { ok, data } = await apiCall('/api/system/kernels/download', 'POST', { version: version });
    if (!ok) {
        statusP.innerHTML = '<span style="color: var(--danger);">Failed: ' + (data.error || 'Unknown error') + '</span>';
        closeBtn.disabled = false;
        return;
    }

    const jobID = data.job_id;
    if (!jobID) {
        statusP.innerHTML = '<span style="color: var(--danger);">Failed: No job ID returned</span>';
        closeBtn.disabled = false;
        return;
    }

    // Poll for progress
    kernelDownloadPollInterval = setInterval(async () => {
        const progResp = await apiCall('/api/system/kernels/download/' + jobID);
        if (progResp.ok) {
            const progress = progResp.data;
            progressBar.style.width = progress.percent + '%%';

            if (progress.error) {
                statusP.innerHTML = '<span style="color: var(--danger);">Error: ' + progress.error + '</span>';
                clearInterval(kernelDownloadPollInterval);
                closeBtn.disabled = false;
            } else if (progress.status === 'completed') {
                statusP.innerHTML = '<span style="color: var(--success);">Download complete!</span>';
                clearInterval(kernelDownloadPollInterval);
                closeBtn.disabled = false;
                // Refresh the lists
                loadInstalledKernels();
                checkKernelUpdates(false);
                // Auto-close dialog after 1.5 seconds
                setTimeout(() => {
                    closeModal('kernelDownloadModal');
                }, 1500);
            } else if (progress.status === 'failed') {
                statusP.innerHTML = '<span style="color: var(--danger);">Failed: ' + (progress.message || 'Unknown error') + '</span>';
                clearInterval(kernelDownloadPollInterval);
                closeBtn.disabled = false;
            } else {
                statusP.textContent = progress.message || 'Downloading...';
            }
        }
    }, 1000);
}

// LDAP Configuration Functions
function deriveBaseDNFromUsername(username) {
    // Extract domain from user@domain.tld format
    const atIndex = username.indexOf('@');
    if (atIndex === -1) return '';
    const domain = username.substring(atIndex + 1);
    if (!domain) return '';
    // Convert domain.tld to DC=domain,DC=tld
    const parts = domain.split('.');
    return parts.map(p => 'DC=' + p).join(',');
}

async function loadLDAPConfig() {
    const { ok, data } = await apiCall('/api/system/ldap');
    const statusText = document.getElementById('ldapStatusText');
    const settingsDiv = document.getElementById('ldapSettings');
    const mappingsCard = document.getElementById('ldapGroupMappingsCard');

    if (ok) {
        const config = data || {};
        // Update status text
        if (config.enabled) {
            statusText.innerHTML = '<span style="color: var(--success);">Enabled</span>';
            mappingsCard.style.display = 'block';
            loadLDAPGroupMappings();
        } else {
            statusText.innerHTML = '<span style="color: var(--text-secondary);">Disabled</span>';
            mappingsCard.style.display = 'none';
        }

        // Populate form fields
        document.getElementById('ldapEnabled').checked = config.enabled || false;
        document.getElementById('ldapServer').value = config.server || '';
        document.getElementById('ldapPort').value = config.port || 389;
        document.getElementById('ldapUseSSL').checked = config.use_ssl || false;
        document.getElementById('ldapUseStartTLS').checked = config.use_starttls || false;
        document.getElementById('ldapSkipVerify').checked = config.skip_verify !== false;
        document.getElementById('ldapBindDN').value = config.bind_dn || '';
        // Auto-derive Base DN from bind_dn and update display
        updateLdapBaseDN();

        // Show/hide settings based on enabled state
        settingsDiv.style.display = config.enabled ? 'block' : 'none';
    } else {
        statusText.innerHTML = '<span style="color: var(--danger);">Error</span>';
    }
}

if (document.getElementById('ldapEnabled')) {
    document.getElementById('ldapEnabled').addEventListener('change', function() {
        document.getElementById('ldapSettings').style.display = this.checked ? 'block' : 'none';
    });
}

if (document.getElementById('ldapUseSSL')) {
    document.getElementById('ldapUseSSL').addEventListener('change', function() {
        if (this.checked) {
            document.getElementById('ldapPort').value = 636;
            document.getElementById('ldapUseStartTLS').checked = false;
        } else {
            document.getElementById('ldapPort').value = 389;
        }
    });
}

// Auto-derive Base DN when username changes
function updateLdapBaseDN() {
    const bindDN = document.getElementById('ldapBindDN');
    const baseDNDisplay = document.getElementById('ldapBaseDNDisplay');
    if (bindDN && baseDNDisplay) {
        const baseDN = deriveBaseDNFromUsername(bindDN.value);
        baseDNDisplay.textContent = baseDN || '-';
        baseDNDisplay.style.color = baseDN ? 'var(--text-primary)' : 'var(--text-secondary)';
    }
}

async function saveLDAPConfig() {
    const bindDN = document.getElementById('ldapBindDN').value;
    const baseDN = deriveBaseDNFromUsername(bindDN);

    const config = {
        enabled: document.getElementById('ldapEnabled').checked,
        server: document.getElementById('ldapServer').value,
        port: parseInt(document.getElementById('ldapPort').value) || 389,
        use_ssl: document.getElementById('ldapUseSSL').checked,
        use_starttls: document.getElementById('ldapUseStartTLS').checked,
        skip_verify: document.getElementById('ldapSkipVerify').checked,
        bind_dn: bindDN,
        bind_password: document.getElementById('ldapBindPassword').value,
        base_dn: baseDN
    };

    const { ok, data } = await apiCall('/api/system/ldap', 'PUT', config);
    if (ok) {
        closeModal('ldapModal');
        loadLDAPConfig();
    } else {
        alert(data.error || 'Failed to save configuration');
    }
}

async function testLDAPConnection() {
    const resultSpan = document.getElementById('ldapTestResult');
    resultSpan.innerHTML = '<span style="color: var(--text-secondary);">Testing...</span>';

    const bindDN = document.getElementById('ldapBindDN').value;
    const baseDN = deriveBaseDNFromUsername(bindDN);

    const config = {
        server: document.getElementById('ldapServer').value,
        port: parseInt(document.getElementById('ldapPort').value) || 389,
        use_ssl: document.getElementById('ldapUseSSL').checked,
        use_starttls: document.getElementById('ldapUseStartTLS').checked,
        skip_verify: document.getElementById('ldapSkipVerify').checked,
        bind_dn: bindDN,
        bind_password: document.getElementById('ldapBindPassword').value,
        base_dn: baseDN
    };

    const { ok, data } = await apiCall('/api/system/ldap/test', 'POST', config);
    if (ok && data.success) {
        resultSpan.innerHTML = '<span style="color: var(--success);"><span class="material-icons" style="font-size: 16px; vertical-align: middle;">check_circle</span> Connection successful</span>';
    } else {
        resultSpan.innerHTML = '<span style="color: var(--danger);"><span class="material-icons" style="font-size: 16px; vertical-align: middle;">error</span> ' + (data.error || 'Connection failed') + '</span>';
    }
}

async function loadLDAPGroupMappings() {
    const { ok, data } = await apiCall('/api/ldap/group-mappings');
    const tbody = document.getElementById('ldapMappingsList');

    if (!ok || !data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No group mappings configured</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(m => ` + "`" + `
        <tr>
            <td>
                <div style="font-weight: 500;">${m.group_name || m.group_dn}</div>
                <small style="color: var(--text-secondary);">${m.group_dn}</small>
            </td>
            <td><span class="badge badge-${m.local_role === 'admin' ? 'info' : 'secondary'}">${m.local_role}</span></td>
            <td>${m.local_group_id || '-'}</td>
            <td>
                <button class="btn btn-danger btn-sm" onclick="deleteLDAPMapping('${m.id}')">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function searchLDAPGroups() {
    const query = document.getElementById('ldapGroupSearch').value.trim();
    const resultsDiv = document.getElementById('ldapGroupSearchResults');

    if (!query) {
        resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center; color: var(--text-secondary);">Enter a search term to find AD groups</p>';
        return;
    }

    resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center;"><span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Searching...</p>';

    const { ok, data } = await apiCall('/api/system/ldap/groups?q=' + encodeURIComponent(query));

    if (!ok) {
        resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center; color: var(--danger);">Error: ' + (data.error || 'Failed to search groups') + '</p>';
        return;
    }

    if (!data || data.length === 0) {
        resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center; color: var(--text-secondary);">No groups found matching "' + query + '"</p>';
        return;
    }

    resultsDiv.innerHTML = data.map(g => ` + "`" + `
        <div style="padding: 12px; border-bottom: 1px solid var(--border-color); cursor: pointer;"
             onclick="selectLDAPGroup('${g.dn.replace(/'/g, "\\'")}', '${(g.name || g.cn || '').replace(/'/g, "\\'")}')"
             onmouseover="this.style.background='var(--bg-tertiary)'"
             onmouseout="this.style.background=''">
            <div style="font-weight: 500;">${g.name || g.cn}</div>
            <small style="color: var(--text-secondary);">${g.dn}</small>
            ${g.description ? '<br><small>' + g.description + '</small>' : ''}
        </div>
    ` + "`" + `).join('');
}

function selectLDAPGroup(dn, name) {
    document.getElementById('selectedGroupDN').value = dn;
    document.getElementById('selectedGroupName').value = name || dn;
    document.getElementById('ldapGroupMappingForm').style.display = 'block';
    document.getElementById('saveLDAPMappingBtn').disabled = false;
    loadLocalGroups();
}

function toggleLocalGroupSelect() {
    const role = document.getElementById('ldapMappingRole').value;
    document.getElementById('localGroupSelectDiv').style.display = role === 'group' ? 'block' : 'none';
}

async function loadLocalGroups() {
    const { ok, data } = await apiCall('/api/groups');
    const select = document.getElementById('ldapMappingLocalGroup');

    if (!ok || !data.groups || data.groups.length === 0) {
        select.innerHTML = '<option value="">No local groups available</option>';
        return;
    }

    select.innerHTML = '<option value="">Select a group...</option>' +
        data.groups.map(g => '<option value="' + g.id + '">' + g.name + '</option>').join('');
}

async function saveLDAPGroupMapping() {
    const dn = document.getElementById('selectedGroupDN').value;
    const name = document.getElementById('selectedGroupName').value;
    const role = document.getElementById('ldapMappingRole').value;
    const localGroupId = document.getElementById('ldapMappingLocalGroup').value;

    if (role === 'group' && !localGroupId) {
        alert('Please select a local group');
        return;
    }

    const mapping = {
        group_dn: dn,
        group_name: name,
        local_role: role,
        local_group_id: localGroupId
    };

    const { ok, data } = await apiCall('/api/ldap/group-mappings', 'POST', mapping);
    if (ok) {
        closeModal('ldapGroupSearchModal');
        resetLDAPGroupModal();
        loadLDAPGroupMappings();
    } else {
        alert(data.error || 'Failed to create mapping');
    }
}

async function deleteLDAPMapping(id) {
    if (!await showConfirm('Are you sure you want to delete this group mapping?')) return;

    const { ok, data } = await apiCall('/api/ldap/group-mappings/' + id, 'DELETE');
    if (ok) {
        loadLDAPGroupMappings();
    } else {
        alert(data.error || 'Failed to delete mapping');
    }
}

function resetLDAPGroupModal() {
    document.getElementById('ldapGroupSearch').value = '';
    document.getElementById('ldapGroupSearchResults').innerHTML = '<p style="padding: 20px; text-align: center; color: var(--text-secondary);">Enter a search term to find AD groups</p>';
    document.getElementById('ldapGroupMappingForm').style.display = 'none';
    document.getElementById('selectedGroupDN').value = '';
    document.getElementById('selectedGroupName').value = '';
    document.getElementById('ldapMappingRole').value = 'admin';
    document.getElementById('localGroupSelectDiv').style.display = 'none';
    document.getElementById('saveLDAPMappingBtn').disabled = true;
}

// Load system status immediately (fast)
loadSystemStatus();
// Load jailer configuration
loadJailerConfig();
// Load proxy configuration
loadProxyConfig();
// Load LDAP configuration
loadLDAPConfig();
// Load cached version info (fast - reads from local JSON cache)
checkFirecrackerUpdate();
// Load installed kernels and cached kernel update info
loadInstalledKernels();
checkKernelUpdates(false);
// Refresh local status every 30 seconds
setInterval(loadSystemStatus, 30000);
</script>
`
}

func (wc *WebConsole) renderUsersPage() string {
	return `
<div class="tab-buttons" style="margin-bottom: 20px;">
    <a href="/users" class="btn btn-primary">
        <span class="material-icons">people</span>
        Users
    </a>
    <a href="/groups" class="btn btn-secondary">
        <span class="material-icons">group_work</span>
        Groups
    </a>
</div>
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
    if (!await showConfirm('Are you sure you want to delete this user?')) return;
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
<div class="tab-buttons" style="margin-bottom: 20px;">
    <a href="/users" class="btn btn-secondary">
        <span class="material-icons">people</span>
        Users
    </a>
    <a href="/groups" class="btn btn-primary">
        <span class="material-icons">group_work</span>
        Groups
    </a>
</div>
<div class="card">
    <div class="card-header">
        <h3>Groups</h3>
        <div style="display: flex; gap: 10px;">
            <button id="browseADBtn" class="btn btn-secondary" onclick="openModal('browseADModal')" style="display: none;">
                <span class="material-icons">domain</span>
                Browse Active Directory
            </button>
            <button class="btn btn-primary" onclick="openModal('createGroupModal')">
                <span class="material-icons">group_add</span>
                Add Group
            </button>
        </div>
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
                    <label>VM Permissions</label>
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
                <div class="form-group">
                    <label>Feature Permissions</label>
                    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-top: 8px;">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_networks" style="width: auto; margin-right: 5px;"> Networks
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_images" style="width: auto; margin-right: 5px;"> Images
                        </label>
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input type="checkbox" name="perm_admin" style="width: auto; margin-right: 5px;"> Administrator
                        </label>
                    </div>
                    <small class="small-text-tip" style="color: var(--text-secondary); font-size: 11px;">Networks: access to network management. Images: access to kernels and root filesystems. Administrator: full access to all features.</small>
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
            <h3>Edit Group: <span id="editGroupName"></span><span id="editGroupADBadge" class="badge badge-info" style="margin-left: 10px; display: none;">Active Directory</span></h3>
            <span class="material-icons modal-close" onclick="closeModal('editGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="editGroupId">
            <input type="hidden" id="editGroupIsAD">

            <div style="display: flex; gap: 20px;">
                <!-- Members Section (Local Groups) -->
                <div id="localMembersSection" style="flex: 1;">
                    <h4 style="margin-bottom: 10px;">Members</h4>
                    <div id="addMemberControls" style="margin-bottom: 10px;">
                        <select id="addMemberSelect" style="width: calc(100% - 80px); display: inline-block;">
                            <option value="">Select user...</option>
                        </select>
                        <button class="btn btn-primary btn-sm" onclick="addMember()">Add</button>
                    </div>
                    <div id="membersList" style="max-height: 200px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;">
                        <p style="color: var(--text-secondary);">No members</p>
                    </div>
                </div>

                <!-- Members Section (AD Groups) -->
                <div id="adMembersSection" style="flex: 1; display: none;">
                    <h4 style="margin-bottom: 10px;">
                        <span class="material-icons" style="vertical-align: middle; font-size: 18px;">domain</span>
                        Active Directory Members
                    </h4>
                    <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 10px;">
                        Members are managed in Active Directory
                    </p>
                    <div id="adMembersList" style="max-height: 250px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;">
                        <p style="color: var(--text-secondary);">Loading...</p>
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

<!-- Browse Active Directory Groups Modal -->
<div id="browseADModal" class="modal">
    <div class="modal-content" style="max-width: 800px;">
        <div class="modal-header">
            <h3>Browse Active Directory Groups</h3>
            <span class="material-icons modal-close" onclick="closeModal('browseADModal')">close</span>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <div style="display: flex; gap: 10px;">
                    <input type="text" id="adGroupSearchInput" placeholder="Search AD groups..." style="flex: 1;">
                    <button type="button" class="btn btn-primary" onclick="searchADGroups()">
                        <span class="material-icons">search</span> Search
                    </button>
                </div>
                <small style="color: var(--text-secondary);">Enter a group name to search or leave empty to list all groups</small>
            </div>
            <div id="adGroupSearchResults" style="max-height: 400px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 8px; margin-top: 15px;">
                <p style="padding: 20px; text-align: center; color: var(--text-secondary);">Click "Search" to browse Active Directory groups</p>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('browseADModal')">Close</button>
        </div>
    </div>
</div>

<!-- Import AD Group Modal -->
<div id="importADGroupModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3>Import Active Directory Group</h3>
            <span class="material-icons modal-close" onclick="closeModal('importADGroupModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="importGroupDN">
            <div class="form-group">
                <label>Group Name</label>
                <input type="text" id="importGroupName" disabled style="background: var(--bg-tertiary);">
            </div>
            <div class="form-group">
                <label>Description</label>
                <input type="text" id="importGroupDescription" placeholder="Optional description">
            </div>
            <div class="form-group">
                <label>VM Permissions</label>
                <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-top: 8px;">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="import_perm_start" checked style="width: auto; margin-right: 5px;"> Start
                    </label>
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="import_perm_stop" checked style="width: auto; margin-right: 5px;"> Stop
                    </label>
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="import_perm_console" checked style="width: auto; margin-right: 5px;"> Console
                    </label>
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="import_perm_edit" style="width: auto; margin-right: 5px;"> Edit
                    </label>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('importADGroupModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="confirmImportADGroup()">
                <span class="material-icons">add</span> Import Group
            </button>
        </div>
    </div>
</div>

<script>
let allUsers = [];
let allVMs = [];
let ldapEnabled = false;

// Check if LDAP is enabled and show/hide Browse AD button
async function checkLDAPStatus() {
    const { ok, data } = await apiCall('/api/system/ldap');
    if (ok && data && data.enabled) {
        ldapEnabled = true;
        document.getElementById('browseADBtn').style.display = 'inline-flex';
    } else {
        ldapEnabled = false;
        document.getElementById('browseADBtn').style.display = 'none';
    }
}

// Check if a group name looks like an AD DN (contains CN= or DC=)
function isADGroup(groupName) {
    return groupName && (groupName.includes('CN=') || groupName.includes('DC='));
}

// Extract the CN (Common Name) from a DN
function extractCNFromDN(dn) {
    if (!dn) return dn;
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
}

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
        const isAD = isADGroup(group.name);
        let memberCount = 0;

        if (isAD && ldapEnabled) {
            // For AD groups, get member count from AD
            const adResp = await apiCall('/api/system/ldap/group-members?dn=' + encodeURIComponent(group.name));
            memberCount = adResp.ok && adResp.data ? adResp.data.count : 0;
        } else {
            // For local groups, get member count from local database
            const membersResp = await apiCall(` + "`" + `/api/groups/${group.id}/members` + "`" + `);
            memberCount = membersResp.ok && membersResp.data.members ? membersResp.data.members.length : 0;
        }

        const vmsResp = await apiCall(` + "`" + `/api/groups/${group.id}/vms` + "`" + `);

        return {
            ...group,
            isAD: isAD,
            displayName: isAD ? extractCNFromDN(group.name) : group.name,
            memberCount: memberCount,
            vmCount: vmsResp.ok && vmsResp.data.vms ? vmsResp.data.vms.length : 0
        };
    }));

    tbody.innerHTML = groupsWithCounts.map(group => ` + "`" + `
        <tr>
            <td>
                <a href="#" onclick="editGroup('${group.id}'); return false;" style="font-weight: bold; text-decoration: none;">
                    ${group.displayName}
                </a>
                ${group.isAD ? '<span class="badge badge-info" style="margin-left: 8px; font-size: 10px;">Active Directory</span>' : ''}
            </td>
            <td>${group.description || '-'}</td>
            <td>
                <ul class="permission-list">
                    ${group.permissions.split(',').map(p => ` + "`" + `<li><span class="material-icons" style="font-size: 14px; color: var(--success); vertical-align: middle;">check</span> ${p.trim()}</li>` + "`" + `).join('')}
                </ul>
            </td>
            <td>
                <span class="badge badge-secondary">${group.memberCount}</span>
                ${group.isAD ? '<small style="color: var(--text-secondary); margin-left: 4px;">(AD)</small>' : ''}
            </td>
            <td><span class="badge badge-secondary">${group.vmCount}</span></td>
            <td>
                <div class="actions">
                    <button class="btn btn-danger btn-sm" onclick="deleteGroup('${group.id}')" title="Delete">
                        <span class="material-icons">delete</span>
                    </button>
                </div>
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
    if (document.querySelector('[name="perm_networks"]').checked) perms.push('networks');
    if (document.querySelector('[name="perm_images"]').checked) perms.push('images');
    if (document.querySelector('[name="perm_admin"]').checked) perms.push('admin');
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

    const isAD = isADGroup(data.name);
    const displayName = isAD ? extractCNFromDN(data.name) : data.name;

    document.getElementById('editGroupId').value = groupId;
    document.getElementById('editGroupIsAD').value = isAD ? 'true' : 'false';
    document.getElementById('editGroupName').textContent = displayName;
    document.getElementById('editGroupADBadge').style.display = isAD ? 'inline' : 'none';

    // Show/hide appropriate members section
    document.getElementById('localMembersSection').style.display = isAD ? 'none' : 'block';
    document.getElementById('adMembersSection').style.display = isAD ? 'block' : 'none';

    // Load all users and VMs for dropdowns
    const [usersResp, vmsResp] = await Promise.all([
        apiCall('/api/users'),
        apiCall('/api/vms')
    ]);
    allUsers = usersResp.ok && usersResp.data.users ? usersResp.data.users : [];
    allVMs = vmsResp.ok && vmsResp.data.vms ? vmsResp.data.vms : [];

    // Load current members and VMs
    await refreshGroupDetails(groupId, isAD, data.name);

    openModal('editGroupModal');
}

async function refreshGroupDetails(groupId, isAD = false, groupDN = '') {
    // Load VMs for the group
    const groupVmsResp = await apiCall(` + "`" + `/api/groups/${groupId}/vms` + "`" + `);
    const currentVMs = groupVmsResp.ok && groupVmsResp.data.vms ? groupVmsResp.data.vms : [];
    const vmIds = currentVMs.map(v => v.vm_id);

    // Populate VM dropdown (exclude already added)
    const vmSelect = document.getElementById('addVmSelect');
    vmSelect.innerHTML = '<option value="">Select VM...</option>';
    allVMs.filter(v => !vmIds.includes(v.id)).forEach(v => {
        vmSelect.innerHTML += ` + "`" + `<option value="${v.id}">${v.name}</option>` + "`" + `;
    });

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

    if (isAD && groupDN) {
        // Load AD group members
        const adMembersList = document.getElementById('adMembersList');
        adMembersList.innerHTML = '<p style="text-align: center; color: var(--text-secondary);"><span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Loading members from Active Directory...</p>';

        const adResp = await apiCall('/api/system/ldap/group-members?dn=' + encodeURIComponent(groupDN) + '&list=true');

        if (!adResp.ok) {
            adMembersList.innerHTML = '<p style="color: var(--danger);">Failed to load AD members: ' + (adResp.data.error || 'Unknown error') + '</p>';
            return;
        }

        const adMembers = adResp.data.members || [];
        if (adMembers.length === 0) {
            adMembersList.innerHTML = '<p style="color: var(--text-secondary);">No members in this group</p>';
        } else {
            adMembersList.innerHTML = adMembers.map(m => ` + "`" + `
                <div style="display: flex; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border-color);">
                    <span class="material-icons" style="font-size: 18px; margin-right: 8px; color: ${m.type === 'group' ? 'var(--warning)' : 'var(--primary)'};">
                        ${m.type === 'group' ? 'folder' : 'person'}
                    </span>
                    <div style="flex: 1;">
                        <div style="font-weight: 500;">${m.display_name || m.cn}</div>
                        ${m.email ? '<small style="color: var(--text-secondary);">' + m.email + '</small>' : ''}
                    </div>
                    <span class="badge badge-${m.type === 'group' ? 'warning' : 'secondary'}" style="font-size: 10px;">${m.type}</span>
                </div>
            ` + "`" + `).join('');
        }
    } else {
        // Load local group members
        const membersResp = await apiCall(` + "`" + `/api/groups/${groupId}/members` + "`" + `);
        const currentMembers = membersResp.ok && membersResp.data.members ? membersResp.data.members : [];
        const memberIds = currentMembers.map(m => m.user_id);

        // Populate member dropdown (exclude already added)
        const memberSelect = document.getElementById('addMemberSelect');
        memberSelect.innerHTML = '<option value="">Select user...</option>';
        allUsers.filter(u => !memberIds.includes(u.id)).forEach(u => {
            memberSelect.innerHTML += ` + "`" + `<option value="${u.id}">${u.username} (${u.role})</option>` + "`" + `;
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
    if (!await showConfirm('Are you sure you want to delete this group?')) return;
    const { ok, data } = await apiCall(` + "`" + `/api/groups/${groupId}` + "`" + `, 'DELETE');
    if (ok) {
        loadGroups();
    } else {
        alert(data.error || 'Failed to delete group');
    }
}

// Search Active Directory groups
async function searchADGroups() {
    const query = document.getElementById('adGroupSearchInput').value.trim();
    const resultsDiv = document.getElementById('adGroupSearchResults');

    resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center;"><span class="material-icons" style="animation: spin 1s linear infinite;">sync</span> Searching...</p>';

    const { ok, data } = await apiCall('/api/system/ldap/groups?q=' + encodeURIComponent(query) + '&limit=100');

    if (!ok) {
        resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center; color: var(--danger);">Error: ' + (data.error || 'Failed to search groups') + '</p>';
        return;
    }

    if (!data || data.length === 0) {
        resultsDiv.innerHTML = '<p style="padding: 20px; text-align: center; color: var(--text-secondary);">No groups found</p>';
        return;
    }

    resultsDiv.innerHTML = '<table style="width: 100%;"><thead><tr><th>Group Name</th><th>Description</th><th style="width: 100px;">Action</th></tr></thead><tbody>' +
        data.map(g => ` + "`" + `
            <tr>
                <td>
                    <strong>${g.cn || g.name}</strong>
                    <br><small style="color: var(--text-secondary);">${g.dn}</small>
                </td>
                <td>${g.description || '-'}</td>
                <td>
                    <button class="btn btn-primary btn-sm" onclick="openImportADGroupModal('${encodeURIComponent(g.dn)}', '${encodeURIComponent(g.cn || g.name)}')">
                        <span class="material-icons">add</span> Import
                    </button>
                </td>
            </tr>
        ` + "`" + `).join('') +
        '</tbody></table>';
}

// Open import AD group modal
function openImportADGroupModal(encodedDN, encodedName) {
    const dn = decodeURIComponent(encodedDN);
    const name = decodeURIComponent(encodedName);

    document.getElementById('importGroupDN').value = dn;
    document.getElementById('importGroupName').value = name;
    document.getElementById('importGroupDescription').value = '';
    document.getElementById('import_perm_start').checked = true;
    document.getElementById('import_perm_stop').checked = true;
    document.getElementById('import_perm_console').checked = true;
    document.getElementById('import_perm_edit').checked = false;

    closeModal('browseADModal');
    openModal('importADGroupModal');
}

// Confirm import AD group
async function confirmImportADGroup() {
    const dn = document.getElementById('importGroupDN').value;
    const description = document.getElementById('importGroupDescription').value;

    // Build permissions
    const perms = [];
    if (document.getElementById('import_perm_start').checked) perms.push('start');
    if (document.getElementById('import_perm_stop').checked) perms.push('stop');
    if (document.getElementById('import_perm_console').checked) perms.push('console');
    if (document.getElementById('import_perm_edit').checked) perms.push('edit');

    const groupData = {
        name: dn,  // Store the DN as the group name to identify it as an AD group
        description: description,
        permissions: perms.join(',')
    };

    const { ok, data } = await apiCall('/api/groups', 'POST', groupData);
    if (ok) {
        closeModal('importADGroupModal');
        loadGroups();
    } else {
        alert(data.error || 'Failed to import group');
    }
}

// Initialize
checkLDAPStatus();
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
                <div class="progress-fill" id="progressFill" style="width: 0%%;"></div>
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
    width: 100%%;
    height: 20px;
    background: #333;
    border-radius: 4px;
    overflow: hidden;
}
.progress-fill {
    height: 100%%;
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
    if (!await showConfirm('Are you sure you want to delete this migration key?')) return;
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
    document.getElementById('progressFill').style.width = '0%%';

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

        document.getElementById('progressFill').style.width = progress + '%%';

        if (bytesTotal > 0) {
            const sentMB = (bytesSent / 1024 / 1024).toFixed(2);
            const totalMB = (bytesTotal / 1024 / 1024).toFixed(2);
            document.getElementById('progressText').textContent =
                'Transferring: ' + sentMB + ' MB / ' + totalMB + ' MB (' + progress.toFixed(1) + '%%)';
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
                    <textarea id="configAddresses" rows="3" placeholder="192.168.1.10/24&#10;10.0.0.1/8" style="width: 100%%; font-family: monospace;"></textarea>
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
                    <textarea id="dnsServersInput" rows="4" placeholder="8.8.8.8&#10;8.8.4.4&#10;1.1.1.1" style="width: 100%%; font-family: monospace;"></textarea>
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
    width: 100%%;
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
    if (!await showConfirm('Are you sure you want to bring down ' + name + '? This may disconnect you!')) {
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
    if (!await showConfirm('Remove address ' + address + ' from ' + ifaceName + '?')) {
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
    if (!await showConfirm('Delete route to ' + destination + '?')) {
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
                    <th>Autorun</th>
                    <th>Permissions</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="vmGroupsTable">
                <tr><td colspan="7">Loading...</td></tr>
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
            <div class="form-group">
                <label class="checkbox-label">
                    <input type="checkbox" id="groupAutorun">
                    <span>Autorun</span>
                </label>
                <small style="color: var(--text-secondary); display: block; margin-top: 4px;">All VMs in this group will start automatically when FireCrackManager starts</small>
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
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="editGroupAutorun">
                        <span>Autorun</span>
                    </label>
                    <small style="color: var(--text-secondary); display: block; margin-top: 4px;">All VMs in this group will start automatically when FireCrackManager starts</small>
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
.checkbox-label { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.checkbox-label input { width: 18px; height: 18px; cursor: pointer; }
.autorun-toggle { cursor: pointer; }
.autorun-toggle .material-icons { font-size: 20px; }
.autorun-toggle.active { color: var(--success); }
.autorun-toggle:not(.active) { color: var(--text-secondary); }
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
        tbody.innerHTML = '<tr><td colspan="7">No VM groups found</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(g => ` + "`" + `
        <tr>
            <td><span class="color-badge" style="background-color: ${g.color || '#3498db'}"></span></td>
            <td>${g.name}</td>
            <td>${g.description || '-'}</td>
            <td>${g.vm_count || 0}</td>
            <td>
                <span class="autorun-toggle ${g.autorun ? 'active' : ''}" onclick="toggleAutorun('${g.id}', ${!g.autorun})" title="${g.autorun ? 'Autorun enabled - click to disable' : 'Autorun disabled - click to enable'}">
                    <span class="material-icons">${g.autorun ? 'play_circle' : 'play_circle_outline'}</span>
                </span>
            </td>
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
        color: document.getElementById('groupColor').value,
        autorun: document.getElementById('groupAutorun').checked
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
    document.getElementById('editGroupAutorun').checked = data.autorun || false;

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
        color: document.getElementById('editGroupColor').value,
        autorun: document.getElementById('editGroupAutorun').checked
    });

    if (ok) {
        closeModal('editGroupModal');
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to update VM group');
    }
}

async function deleteVMGroup() {
    if (!await showConfirm('Are you sure you want to delete this VM group?')) return;

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

async function toggleAutorun(groupId, enable) {
    // Get current group data first
    const groupData = vmGroups.find(g => g.id === groupId);
    if (!groupData) return;

    const { ok, data } = await apiCall('/api/vmgroups/' + groupId, 'PUT', {
        name: groupData.name,
        description: groupData.description || '',
        color: groupData.color || '#3498db',
        autorun: enable
    });

    if (ok) {
        loadVMGroups();
    } else {
        alert(data.error || 'Failed to toggle autorun');
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
        <h3><span class="material-icons" style="vertical-align: middle; margin-right: 8px;">account_circle</span><span id="accountHeaderUsername">My Account</span></h3>
        <button id="changePasswordHeaderBtn" class="btn btn-primary" onclick="openModal('changePasswordModal')">
            <span class="material-icons">key</span> Change Password
        </button>
    </div>
    <div class="card-body">
        <div class="account-info">
            <div class="account-details">
                <table style="width: 100%%; max-width: 500px;">
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
    width: 100%%;
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
    document.getElementById('accountHeaderUsername').textContent = data.user.username;
    document.getElementById('accountUsername').textContent = data.user.username;
    document.getElementById('accountEmail').textContent = data.user.email || '-';
    document.getElementById('accountRole').innerHTML = '<span class="badge badge-' + (data.user.role === 'admin' ? 'success' : 'info') + '">' + data.user.role + '</span>';
    document.getElementById('accountCreatedAt').textContent = formatDate(data.user.created_at);

    // Hide Change Password button for LDAP/AD users
    if (data.user.ldap_user) {
        const changePasswordBtn = document.getElementById('changePasswordHeaderBtn');
        if (changePasswordBtn) {
            changePasswordBtn.style.display = 'none';
        }
    }

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

func (wc *WebConsole) renderAppliancesPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Exported VMs</h3>
    </div>
    <div class="card-body">
        <table class="data-table" style="table-layout: fixed; width: 100%%;">
            <thead>
                <tr>
                    <th style="width: auto;">NAME</th>
                    <th style="width: 100px;">OWNER</th>
                    <th style="width: 180px;">EXPORTED DATE</th>
                    <th style="width: 100px;">SIZE</th>
                    <th style="width: 80px; text-align: center;">ACTIONS</th>
                </tr>
            </thead>
            <tbody id="appliancesList">
                <tr>
                    <td colspan="5">Loading...</td>
                </tr>
            </tbody>
        </table>
        <!-- Delete progress bar -->
        <div id="deleteApplianceProgress" style="display: none; margin-top: 15px; padding: 15px; background: var(--bg-secondary); border-radius: 8px;">
            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                <span class="material-icons" style="color: var(--danger); margin-right: 8px; animation: spin 1s linear infinite;">sync</span>
                <span id="deleteProgressText" style="color: var(--text-primary);">Deleting appliance...</span>
            </div>
            <div style="background: var(--bg-tertiary); border-radius: 4px; height: 8px; overflow: hidden;">
                <div id="deleteProgressBar" style="background: var(--danger); height: 100%%; width: 0%%; transition: width 0.3s ease;"></div>
            </div>
        </div>
    </div>
</div>

<!-- Appliance Actions Modal -->
<div id="applianceActionsModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3 id="appActionsTitle">Appliance Actions</h3>
            <span class="material-icons modal-close" onclick="closeModal('applianceActionsModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="appActionsFilename">
            <input type="hidden" id="appActionsVmName">
            <input type="hidden" id="appActionsCanWrite">
            <input type="hidden" id="appActionsDescription">

            <div style="margin-bottom: 20px;">
                <p style="color: var(--text-secondary); margin-bottom: 5px;">Filename:</p>
                <code id="appActionsFilenameDisplay" style="font-size: 12px; word-break: break-all;"></code>
            </div>
            <div style="margin-bottom: 20px;" id="appActionsDescriptionContainer">
                <p style="color: var(--text-secondary); margin-bottom: 5px;">Description:</p>
                <span id="appActionsDescriptionDisplay" style="font-size: 13px; font-style: italic; color: var(--text-muted);">No description</span>
            </div>

            <div style="display: flex; flex-direction: column; gap: 10px;">
                <button class="btn btn-success" onclick="openRestoreFromActions()" style="justify-content: flex-start;">
                    <span class="material-icons">restore</span>
                    Restore as New VM
                </button>
                <button class="btn btn-primary" onclick="downloadFromActions()" style="justify-content: flex-start;">
                    <span class="material-icons">download</span>
                    Download Appliance
                </button>
                <button class="btn btn-secondary" id="btnManagePrivileges" onclick="openPrivilegesFromActions()" style="justify-content: flex-start; display: none;">
                    <span class="material-icons">security</span>
                    Manage Privileges
                </button>
                <button class="btn btn-secondary" id="btnEditApplianceDescription" onclick="openEditApplianceDescription()" style="justify-content: flex-start; display: none;">
                    <span class="material-icons">edit_note</span>
                    Edit Description
                </button>
                <hr style="border: none; border-top: 1px solid var(--border); margin: 10px 0;">
                <button class="btn btn-danger" id="btnDeleteAppliance" onclick="deleteFromActions()" style="justify-content: flex-start; display: none;">
                    <span class="material-icons">delete</span>
                    Delete Appliance
                </button>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('applianceActionsModal')">Close</button>
        </div>
    </div>
</div>

<!-- Privileges Modal -->
<div id="privilegesModal" class="modal">
    <div class="modal-content" style="max-width: 600px;">
        <div class="modal-header">
            <h3>Manage Privileges: <span id="privModalFilename"></span></h3>
            <span class="material-icons modal-close" onclick="closeModal('privilegesModal')">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="privFilename">

            <!-- Add Privilege Form -->
            <div style="margin-bottom: 20px; padding: 15px; background: var(--bg-secondary); border-radius: 8px;">
                <h4 style="margin-bottom: 10px;">Add Privilege</h4>
                <div style="display: flex; gap: 10px; align-items: end; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 150px;">
                        <label style="font-size: 12px;">Type</label>
                        <select id="privType" onchange="updatePrivTarget()" style="width: 100%%;">
                            <option value="user">User</option>
                            <option value="group">Group</option>
                        </select>
                    </div>
                    <div style="flex: 2; min-width: 200px;">
                        <label style="font-size: 12px;">Target</label>
                        <select id="privTarget" style="width: 100%%;">
                            <option value="">Select...</option>
                        </select>
                    </div>
                    <div style="min-width: 80px;">
                        <label style="font-size: 12px; display: flex; align-items: center; gap: 5px;">
                            <input type="checkbox" id="privRead" checked style="width: auto;"> Read
                        </label>
                    </div>
                    <div style="min-width: 80px;">
                        <label style="font-size: 12px; display: flex; align-items: center; gap: 5px;">
                            <input type="checkbox" id="privWrite" style="width: auto;"> Write
                        </label>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="addPrivilege()">
                        <span class="material-icons">add</span> Add
                    </button>
                </div>
            </div>

            <!-- Privileges List -->
            <h4 style="margin-bottom: 10px;">Current Privileges</h4>
            <div id="privilegesList" style="max-height: 300px; overflow-y: auto;">
                <p style="color: var(--text-secondary);">Loading...</p>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('privilegesModal')">Close</button>
        </div>
    </div>
</div>

<!-- Edit Appliance Description Modal -->
<div id="editApplianceDescModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3>Edit Appliance Description</h3>
            <span class="material-icons modal-close" onclick="closeEditAppDescModal()">close</span>
        </div>
        <div class="modal-body">
            <input type="hidden" id="editAppDescFilename">
            <p style="margin-bottom: 10px; color: var(--text-secondary);">
                Appliance: <strong id="editAppDescFilenameDisplay"></strong>
            </p>
            <div class="form-group">
                <label for="editAppDescText">Description</label>
                <textarea id="editAppDescText" rows="4" placeholder="Enter appliance description..." style="width: 100%%;"></textarea>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeEditAppDescModal()">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="saveApplianceDescription()">Save</button>
        </div>
    </div>
</div>

<!-- Restore Appliance Modal -->
<div id="restoreModal" class="modal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3>Restore Appliance</h3>
            <span class="material-icons modal-close" onclick="closeRestoreModal()">close</span>
        </div>
        <form id="restoreForm" onsubmit="submitRestore(event)">
            <div class="modal-body">
                <input type="hidden" id="restoreFilename">
                <!-- Form fields -->
                <div id="restoreFormFields">
                    <p style="margin-bottom: 15px; color: var(--text-secondary);">
                        This will create a new VM from the selected appliance.
                    </p>
                    <div class="form-group">
                        <label for="restoreVmName">VM Name</label>
                        <input type="text" name="name" id="restoreVmName" required placeholder="Enter VM name">
                    </div>
                    <div class="form-group">
                        <label for="restoreKernelSelect">Kernel</label>
                        <select name="kernel_id" id="restoreKernelSelect" required>
                            <option value="">Loading kernels...</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin-top: 15px;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="restoreExpandDisk" onchange="toggleExpandDiskOptions()">
                            <span>Expand Disk After Restore</span>
                        </label>
                        <small style="color: var(--text-secondary); font-size: 11px;">Increase the disk size during restore operation</small>
                    </div>
                    <div id="restoreExpandDiskOptions" style="display: none; padding: 10px; background: var(--surface); border-radius: 4px; margin-top: 10px;">
                        <div class="form-group">
                            <label for="restoreExpandDiskGB">New Disk Size (GB)</label>
                            <input type="number" id="restoreExpandDiskGB" min="1" step="1" placeholder="e.g., 10">
                            <small style="color: var(--text-secondary); font-size: 11px;">The disk will be expanded to this size in GB. Must be larger than the current disk size.</small>
                        </div>
                    </div>
                </div>
                <!-- Progress display -->
                <div id="restoreProgress" style="display: none;">
                    <div style="text-align: center; margin-bottom: 15px;">
                        <span class="material-icons" style="font-size: 48px; color: var(--primary); animation: spin 1s linear infinite;">sync</span>
                    </div>
                    <div id="restoreStage" style="text-align: center; margin-bottom: 10px; color: var(--text-secondary);">
                        Preparing restore...
                    </div>
                    <div style="background: #e0e0e0; border-radius: 4px; height: 20px; overflow: hidden;">
                        <div id="restoreProgressBar" style="background: linear-gradient(90deg, #1ab394, #23c6a5); height: 100%%; width: 0%%; transition: width 0.3s ease;"></div>
                    </div>
                    <div id="restorePercent" style="text-align: center; margin-top: 5px; font-weight: 500;">0</div>
                </div>
            </div>
            <div class="modal-footer" id="restoreFooter">
                <button type="button" class="btn btn-secondary" onclick="closeRestoreModal()">Cancel</button>
                <button type="submit" class="btn btn-success" id="restoreSubmitBtn">
                    <span class="material-icons">restore</span> Restore
                </button>
            </div>
        </form>
    </div>
</div>

<script>
let allUsers = [];
let allGroups = [];
let kernelsLoaded = false;

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function loadAppliances() {
    const tbody = document.getElementById('appliancesList');

    try {
        const response = await fetch('/api/appliances', { credentials: 'include' });
        const data = await response.json();

        if (!response.ok) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="material-icons">error</span><p>' + (data.error || 'Failed to load appliances') + '</p></td></tr>';
            return;
        }

        if (!data.appliances || data.appliances.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="material-icons">inventory_2</span><p>No exported appliances</p><small>Export a VM from the Virtual Machines page to create an appliance</small></td></tr>';
            return;
        }

        tbody.innerHTML = data.appliances.map(app => ` + "`" + `
            <tr id="appliance-row-${app.filename.replace(/[^a-zA-Z0-9]/g, '_')}">
                <td>
                    <a href="#" onclick="openApplianceActions('${app.filename}', '${app.vm_name}', ${app.is_owner || app.can_write}, '${encodeURIComponent(app.description || '')}'); return false;" style="text-decoration: none; color: inherit;">
                        <svg xmlns="http://www.w3.org/2000/svg" height="48px" viewBox="0 -960 960 960" width="48px" fill="#1ab394" style="vertical-align: middle; margin-right: 8px;"><path d="M480-80q-10 0-19-3t-17-9L204-252q-8-6-12-14.5T188-284v-248q0-9 4-17.5t12-14.5l240-160q8-6 17-9t19-3q10 0 19 3t17 9l240 160q8 6 12 14.5t4 17.5v248q0 9-4 17.5T756-252L516-92q-8 6-17 9t-19 3Zm0-308 168-110-168-112-168 112 168 110Zm40 203 160-106v-150l-160 106v150Zm-80 0v-150l-160-106v150l160 106Zm40-203Z"/></svg>
                        <div class="appliance-name">${app.vm_name}</div>
                    </a>
                    <div class="appliance-explain">${app.description || app.filename}</div>
                </td>
                <td>
                    ${app.owner_name ? '<span class="badge badge-secondary">' + app.owner_name + '</span>' : '<span style="color: var(--text-secondary);">-</span>'}
                    ${app.is_owner ? '<span class="badge badge-primary" style="margin-left: 4px;">You</span>' : ''}
                </td>
                <td>${app.exported_date}</td>
                <td>${formatBytes(app.size)}</td>
                <td style="text-align: center;">
                    ${app.can_write ? ` + "`" + `
                        <button class="btn btn-icon btn-danger" onclick="deleteApplianceWithProgress('${app.filename}', '${app.vm_name}'); event.stopPropagation();" title="Delete" style="padding: 6px;">
                            <span class="material-icons" style="font-size: 18px;">delete</span>
                        </button>
                    ` + "`" + ` : '<span style="color: var(--text-secondary);">-</span>'}
                </td>
            </tr>
        ` + "`" + `).join('');
    } catch (error) {
        console.error('loadAppliances error:', error);
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="material-icons">error</span><p>Error: ' + error.message + '</p></td></tr>';
    }
}

async function deleteApplianceWithProgress(filename, vmName) {
    if (!await showConfirm('Are you sure you want to delete the appliance "' + vmName + '"?\n\nThis action cannot be undone.')) {
        return;
    }

    const progressContainer = document.getElementById('deleteApplianceProgress');
    const progressBar = document.getElementById('deleteProgressBar');
    const progressText = document.getElementById('deleteProgressText');
    const rowId = 'appliance-row-' + filename.replace(/[^a-zA-Z0-9]/g, '_');
    const row = document.getElementById(rowId);

    // Show progress
    progressContainer.style.display = 'block';
    progressText.textContent = 'Deleting "' + vmName + '"...';
    progressBar.style.width = '30%';

    // Fade out the row
    if (row) {
        row.style.opacity = '0.5';
        row.style.pointerEvents = 'none';
    }

    try {
        progressBar.style.width = '60%';

        const response = await fetch('/api/appliances/' + encodeURIComponent(filename), {
            method: 'DELETE',
            credentials: 'include'
        });

        progressBar.style.width = '90%';

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to delete appliance');
        }

        progressBar.style.width = '100%';
        progressText.textContent = 'Deleted successfully!';
        progressBar.style.background = 'var(--success)';

        // Remove the row with animation
        if (row) {
            row.style.transition = 'all 0.3s ease';
            row.style.transform = 'translateX(-100%)';
            row.style.opacity = '0';
            setTimeout(() => row.remove(), 300);
        }

        // Hide progress after a short delay and reload
        setTimeout(() => {
            progressContainer.style.display = 'none';
            progressBar.style.width = '0%';
            progressBar.style.background = 'var(--danger)';
            loadAppliances();
        }, 1500);

    } catch (error) {
        console.error('Delete appliance error:', error);
        progressText.textContent = 'Error: ' + error.message;
        progressBar.style.width = '100%';
        progressBar.style.background = 'var(--danger)';

        // Restore the row
        if (row) {
            row.style.opacity = '1';
            row.style.pointerEvents = 'auto';
        }

        // Hide progress after showing error
        setTimeout(() => {
            progressContainer.style.display = 'none';
            progressBar.style.width = '0%';
        }, 3000);
    }
}

function openApplianceActions(filename, vmName, canWrite, descEncoded) {
    const description = decodeURIComponent(descEncoded || '');
    document.getElementById('appActionsFilename').value = filename;
    document.getElementById('appActionsVmName').value = vmName;
    document.getElementById('appActionsCanWrite').value = canWrite ? '1' : '0';
    document.getElementById('appActionsDescription').value = description;
    document.getElementById('appActionsTitle').textContent = vmName;
    document.getElementById('appActionsFilenameDisplay').textContent = filename;
    document.getElementById('appActionsDescriptionDisplay').textContent = description || 'No description';

    // Show/hide write-only actions
    document.getElementById('btnManagePrivileges').style.display = canWrite ? 'flex' : 'none';
    document.getElementById('btnEditApplianceDescription').style.display = canWrite ? 'flex' : 'none';
    document.getElementById('btnDeleteAppliance').style.display = canWrite ? 'flex' : 'none';

    openModal('applianceActionsModal');
}

function openRestoreFromActions() {
    const filename = document.getElementById('appActionsFilename').value;
    const vmName = document.getElementById('appActionsVmName').value;
    closeModal('applianceActionsModal');
    openRestoreModal(filename, vmName);
}

function downloadFromActions() {
    const filename = document.getElementById('appActionsFilename').value;
    closeModal('applianceActionsModal');
    downloadAppliance(filename);
}

function openPrivilegesFromActions() {
    const filename = document.getElementById('appActionsFilename').value;
    closeModal('applianceActionsModal');
    openPrivilegesModal(filename);
}

async function deleteFromActions() {
    const filename = document.getElementById('appActionsFilename').value;
    closeModal('applianceActionsModal');
    await deleteAppliance(filename);
}

// Store data for reopening actions modal
let editAppDescData = {};

function openEditApplianceDescription() {
    // Store current modal data
    editAppDescData = {
        filename: document.getElementById('appActionsFilename').value,
        vmName: document.getElementById('appActionsVmName').value,
        canWrite: document.getElementById('appActionsCanWrite').value === '1',
        description: document.getElementById('appActionsDescription').value
    };

    // Set edit modal values
    document.getElementById('editAppDescFilename').value = editAppDescData.filename;
    document.getElementById('editAppDescFilenameDisplay').textContent = editAppDescData.filename;
    document.getElementById('editAppDescText').value = editAppDescData.description;

    // Close actions modal, open edit modal
    closeModal('applianceActionsModal');
    openModal('editApplianceDescModal');
}

function closeEditAppDescModal() {
    // Close edit modal
    closeModal('editApplianceDescModal');
    // Reopen actions modal with stored data
    openApplianceActions(editAppDescData.filename, editAppDescData.vmName, editAppDescData.canWrite, encodeURIComponent(editAppDescData.description));
}

async function saveApplianceDescription() {
    const filename = document.getElementById('editAppDescFilename').value;
    const description = document.getElementById('editAppDescText').value.trim();

    if (!filename) {
        showToast('No appliance selected', 'error');
        return;
    }

    try {
        const { ok, data } = await apiCall('/api/appliances/' + encodeURIComponent(filename), 'PUT', { description: description });

        if (ok) {
            showToast('Description updated successfully', 'success');
            // Update stored data
            editAppDescData.description = description;
            // Close edit modal
            closeModal('editApplianceDescModal');
            // Reopen actions modal with updated description
            openApplianceActions(editAppDescData.filename, editAppDescData.vmName, editAppDescData.canWrite, encodeURIComponent(description));
            // Refresh the table in background
            loadAppliances();
        } else {
            showToast(data.error || 'Failed to update description', 'error');
        }
    } catch (err) {
        console.error('Save description error:', err);
        showToast('Error saving description: ' + err.message, 'error');
    }
}

function downloadAppliance(filename) {
    window.location.href = '/api/appliances/' + encodeURIComponent(filename);
}

async function openRestoreModal(filename, vmName) {
    document.getElementById('restoreFilename').value = filename;
    document.getElementById('restoreVmName').value = vmName || '';

    // Load kernels if not already loaded
    if (!kernelsLoaded) {
        try {
            const response = await fetch('/api/kernels', { credentials: 'include' });
            const data = await response.json();

            const select = document.getElementById('restoreKernelSelect');
            if (data.kernels && data.kernels.length > 0) {
                select.innerHTML = data.kernels.map(k =>
                    ` + "`" + `<option value="${k.id}">${k.name} (${k.version})</option>` + "`" + `
                ).join('');
                kernelsLoaded = true;
            } else {
                select.innerHTML = '<option value="">No kernels available</option>';
            }
        } catch (error) {
            document.getElementById('restoreKernelSelect').innerHTML = '<option value="">Error loading kernels</option>';
        }
    }

    openModal('restoreModal');
}

let restoreProgressInterval = null;

function closeRestoreModal() {
    if (restoreProgressInterval) {
        clearInterval(restoreProgressInterval);
        restoreProgressInterval = null;
    }
    closeModal('restoreModal');
    // Reset modal state
    document.getElementById('restoreFormFields').style.display = 'block';
    document.getElementById('restoreProgress').style.display = 'none';
    document.getElementById('restoreFooter').style.display = 'flex';
    document.getElementById('restoreSubmitBtn').disabled = false;
    document.getElementById('restoreSubmitBtn').innerHTML = '<span class="material-icons">restore</span> Restore';
    // Reset expand disk fields
    document.getElementById('restoreExpandDisk').checked = false;
    document.getElementById('restoreExpandDiskOptions').style.display = 'none';
    document.getElementById('restoreExpandDiskGB').value = '';
}

function toggleExpandDiskOptions() {
    const checkbox = document.getElementById('restoreExpandDisk');
    const options = document.getElementById('restoreExpandDiskOptions');
    options.style.display = checkbox.checked ? 'block' : 'none';
}

async function submitRestore(event) {
    event.preventDefault();

    const filename = document.getElementById('restoreFilename').value;
    const name = document.getElementById('restoreVmName').value;
    const kernelId = document.getElementById('restoreKernelSelect').value;
    const expandDisk = document.getElementById('restoreExpandDisk').checked;
    const expandDiskGB = expandDisk ? parseInt(document.getElementById('restoreExpandDiskGB').value) || 0 : 0;

    if (!name || !kernelId) {
        alert('Please fill in all fields');
        return;
    }

    if (expandDisk && expandDiskGB <= 0) {
        alert('Please enter a valid disk size in GB');
        return;
    }

    const submitBtn = document.getElementById('restoreSubmitBtn');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="material-icons">hourglass_empty</span> Starting...';

    try {
        const requestBody = { name: name, kernel_id: kernelId };
        if (expandDiskGB > 0) {
            requestBody.expand_disk_gb = expandDiskGB;
        }

        const response = await fetch('/api/appliances/restore/' + encodeURIComponent(filename), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (response.ok && data.progress_key) {
            // Show progress UI
            document.getElementById('restoreFormFields').style.display = 'none';
            document.getElementById('restoreProgress').style.display = 'block';
            document.getElementById('restoreFooter').style.display = 'none';

            // Start polling for progress
            pollRestoreProgress(data.progress_key, name);
        } else {
            alert(data.error || 'Failed to start restore');
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span class="material-icons">restore</span> Restore';
        }
    } catch (error) {
        alert('Error restoring appliance: ' + error.message);
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span class="material-icons">restore</span> Restore';
    }
}

function pollRestoreProgress(progressKey, vmName) {
    restoreProgressInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/operations/' + progressKey, { credentials: 'include' });
            const progress = await response.json();

            if (progress.error) {
                clearInterval(restoreProgressInterval);
                restoreProgressInterval = null;
                alert('Restore failed: ' + progress.error);
                closeRestoreModal();
                return;
            }

            // Update progress UI
            document.getElementById('restoreStage').textContent = progress.stage || 'Processing...';
            document.getElementById('restoreProgressBar').style.width = (progress.percent || 0) + '%%';
            document.getElementById('restorePercent').innerHTML = (progress.percent || 0) + percentIcon(14);

            if (progress.status === 'completed') {
                clearInterval(restoreProgressInterval);
                restoreProgressInterval = null;

                // Show success
                document.getElementById('restoreProgress').innerHTML = ` + "`" + `
                    <div style="text-align: center;">
                        <span class="material-icons" style="font-size: 64px; color: #1ab394;">check_circle</span>
                        <h3 style="margin: 15px 0;">Restore Complete!</h3>
                        <p style="color: var(--text-secondary);">VM "${progress.result_name || vmName}" has been created.</p>
                        <button class="btn btn-success" onclick="window.location.href='/vms'" style="margin-top: 15px;">
                            <span class="material-icons">visibility</span> View VMs
                        </button>
                    </div>
                ` + "`" + `;
            } else if (progress.status === 'error') {
                clearInterval(restoreProgressInterval);
                restoreProgressInterval = null;
                alert('Restore failed: ' + (progress.error || 'Unknown error'));
                closeRestoreModal();
            }
        } catch (error) {
            console.error('Error polling progress:', error);
        }
    }, 500);
}

async function deleteAppliance(filename) {
    if (!await showConfirm('Are you sure you want to delete this appliance?\n\n' + filename)) {
        return;
    }

    try {
        const response = await fetch('/api/appliances/' + encodeURIComponent(filename), {
            method: 'DELETE',
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok) {
            loadAppliances();
        } else {
            alert(data.error || 'Failed to delete appliance');
        }
    } catch (error) {
        alert('Error deleting appliance: ' + error.message);
    }
}

async function openPrivilegesModal(filename) {
    document.getElementById('privFilename').value = filename;
    document.getElementById('privModalFilename').textContent = filename;

    // Load users and groups for dropdowns
    const [usersResp, groupsResp] = await Promise.all([
        fetch('/api/users', { credentials: 'include' }).then(r => r.json()).catch(() => ({ users: [] })),
        fetch('/api/groups', { credentials: 'include' }).then(r => r.json()).catch(() => ({ groups: [] }))
    ]);
    allUsers = usersResp.users || [];
    allGroups = groupsResp.groups || [];

    updatePrivTarget();
    await loadPrivileges(filename);
    openModal('privilegesModal');
}

function updatePrivTarget() {
    const type = document.getElementById('privType').value;
    const select = document.getElementById('privTarget');

    if (type === 'user') {
        select.innerHTML = '<option value="">Select user...</option>' +
            allUsers.map(u => ` + "`" + `<option value="${u.id}">${u.username}</option>` + "`" + `).join('');
    } else {
        select.innerHTML = '<option value="">Select group...</option>' +
            allGroups.map(g => ` + "`" + `<option value="${g.id}">${g.name}</option>` + "`" + `).join('');
    }
}

async function loadPrivileges(filename) {
    const container = document.getElementById('privilegesList');

    try {
        const response = await fetch('/api/appliances/' + encodeURIComponent(filename) + '/privileges', { credentials: 'include' });
        const data = await response.json();

        if (!response.ok) {
            container.innerHTML = '<p style="color: var(--danger);">' + (data.error || 'Failed to load privileges') + '</p>';
            return;
        }

        const privileges = data.privileges || [];

        if (privileges.length === 0) {
            container.innerHTML = '<p style="color: var(--text-secondary);">No privileges assigned. Only the owner can access this appliance.</p>';
            return;
        }

        container.innerHTML = '<table style="width: 100%%;"><thead><tr><th>Type</th><th>Name</th><th>Read</th><th>Write</th><th></th></tr></thead><tbody>' +
            privileges.map(p => ` + "`" + `
                <tr>
                    <td><span class="badge badge-${p.user_id ? 'primary' : 'secondary'}">${p.user_id ? 'User' : 'Group'}</span></td>
                    <td>${p.username || p.group_name || 'Unknown'}</td>
                    <td>${p.can_read ? '<span class="material-icons" style="color: var(--success);">check</span>' : '<span class="material-icons" style="color: var(--text-secondary);">close</span>'}</td>
                    <td>${p.can_write ? '<span class="material-icons" style="color: var(--success);">check</span>' : '<span class="material-icons" style="color: var(--text-secondary);">close</span>'}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="removePrivilege('${p.user_id ? 'user' : 'group'}', '${p.user_id || p.group_id}')" title="Remove">
                            <span class="material-icons">delete</span>
                        </button>
                    </td>
                </tr>
            ` + "`" + `).join('') + '</tbody></table>';
    } catch (error) {
        container.innerHTML = '<p style="color: var(--danger);">Error loading privileges</p>';
    }
}

async function addPrivilege() {
    const filename = document.getElementById('privFilename').value;
    const type = document.getElementById('privType').value;
    const targetId = document.getElementById('privTarget').value;
    const canRead = document.getElementById('privRead').checked;
    const canWrite = document.getElementById('privWrite').checked;

    if (!targetId) {
        alert('Please select a ' + type);
        return;
    }

    if (!canRead && !canWrite) {
        alert('Please select at least read or write permission');
        return;
    }

    const body = {
        can_read: canRead,
        can_write: canWrite
    };

    if (type === 'user') {
        body.user_id = parseInt(targetId);
    } else {
        body.group_id = targetId;
    }

    try {
        const response = await fetch('/api/appliances/' + encodeURIComponent(filename) + '/privileges', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(body)
        });
        const data = await response.json();

        if (response.ok) {
            document.getElementById('privTarget').value = '';
            await loadPrivileges(filename);
        } else {
            alert(data.error || 'Failed to add privilege');
        }
    } catch (error) {
        alert('Error adding privilege: ' + error.message);
    }
}

async function removePrivilege(type, id) {
    const filename = document.getElementById('privFilename').value;

    if (!await showConfirm('Are you sure you want to remove this privilege?')) {
        return;
    }

    try {
        const response = await fetch('/api/appliances/' + encodeURIComponent(filename) + '/privileges/' + type + '/' + id, {
            method: 'DELETE',
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok) {
            await loadPrivileges(filename);
        } else {
            alert(data.error || 'Failed to remove privilege');
        }
    } catch (error) {
        alert('Error removing privilege: ' + error.message);
    }
}

// Load appliances on page load
loadAppliances();
</script>
`
}

func (wc *WebConsole) renderStorePage() string {
	return `
<style>
.store-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.store-card {
    background: var(--card-bg);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.store-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
}

.store-card-header .material-icons {
    font-size: 32px;
    color: var(--primary);
}

.store-card-title {
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0;
}

.store-card-description {
    color: var(--text-muted);
    font-size: 0.9rem;
    margin-bottom: 16px;
    line-height: 1.4;
}

.store-card-meta {
    display: flex;
    gap: 16px;
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-bottom: 16px;
}

.store-card-meta span {
    display: flex;
    align-items: center;
    gap: 4px;
}

.store-card-meta .material-icons {
    font-size: 16px;
}

.store-card-actions {
    display: flex;
    gap: 8px;
}

.download-progress {
    display: none;
    margin-top: 12px;
}

.download-progress.active {
    display: block;
}

.progress-bar-container {
    background: var(--border);
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
    margin-bottom: 8px;
}

.progress-bar-fill {
    background: var(--primary);
    height: 100%%;
    width: 0%%;
    transition: width 0.3s ease;
}

.progress-info {
    font-size: 0.8rem;
    color: var(--text-muted);
    display: flex;
    justify-content: space-between;
}

.store-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.store-header h3 {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 8px;
}

.store-header .material-icons {
    color: var(--primary);
}

.last-update {
    font-size: 0.85rem;
    color: var(--text-muted);
}

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-muted);
}

.empty-state .material-icons {
    font-size: 64px;
    margin-bottom: 16px;
    opacity: 0.5;
}

.store-card.downloading .btn-download {
    display: none;
}

.store-card.downloading .download-progress {
    display: block;
}

.btn-download.completed {
    background: var(--success);
}
</style>

<div class="store-header">
    <h3>
        <span class="material-icons">store</span>
        Appliance Store
    </h3>
    <div style="display: flex; align-items: center; gap: 16px;">
        <span class="last-update" id="lastUpdate">Loading...</span>
        <button class="btn btn-secondary" onclick="refreshCatalog()">
            <span class="material-icons">refresh</span>
            Refresh
        </button>
    </div>
</div>

<div id="storeContent">
    <div class="empty-state">
        <span class="material-icons">hourglass_empty</span>
        <p>Loading store catalog...</p>
    </div>
</div>

<script>
let activeDownloads = {};

async function loadStore() {
    try {
        const response = await fetch('/api/store');
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to load store');
        }

        renderStore(data);
    } catch (error) {
        document.getElementById('storeContent').innerHTML = ` + "`" + `
            <div class="empty-state">
                <span class="material-icons">error_outline</span>
                <p>Failed to load store: ${error.message}</p>
                <button class="btn btn-primary" onclick="loadStore()">Retry</button>
            </div>
        ` + "`" + `;
    }
}

function renderStore(data) {
    const container = document.getElementById('storeContent');
    const lastUpdate = document.getElementById('lastUpdate');

    if (data.last_update) {
        const date = new Date(data.last_update);
        if (date.getTime() > 0) {
            lastUpdate.textContent = 'Last updated: ' + date.toLocaleString();
        } else {
            lastUpdate.textContent = 'Catalog not yet loaded';
        }
    }

    if (!data.appliances || data.appliances.length === 0) {
        container.innerHTML = ` + "`" + `
            <div class="empty-state">
                <span class="material-icons">inventory_2</span>
                <p>No appliances available in the store</p>
                <button class="btn btn-primary" onclick="refreshCatalog()">Refresh Catalog</button>
            </div>
        ` + "`" + `;
        return;
    }

    let html = '<div class="store-grid">';

    for (const app of data.appliances) {
        const sizeFormatted = formatBytes(app.size);
        const dateFormatted = app.date ? new Date(app.date * 1000).toLocaleDateString() : 'Unknown';
        const partsCount = app.parts ? app.parts.length : 0;

        html += ` + "`" + `
            <div class="store-card" id="card-${app.name}" data-name="${app.name}">
                <div class="store-card-header">
                    <span class="material-icons">apps</span>
                    <h4 class="store-card-title">${escapeHtml(app.title || app.name)}</h4>
                </div>
                <p class="store-card-description">${escapeHtml(app.description || 'No description available')}</p>
                <div class="store-card-meta">
                    <span><span class="material-icons">folder</span> ${sizeFormatted}</span>
                    <span><span class="material-icons">calendar_today</span> ${dateFormatted}</span>
                    <span><span class="material-icons">layers</span> ${partsCount} parts</span>
                </div>
                <div class="store-card-actions">
                    <button class="btn btn-primary btn-download" onclick="startDownload('${app.name}')">
                        <span class="material-icons">download</span>
                        Download
                    </button>
                </div>
                <div class="download-progress">
                    <div class="progress-bar-container">
                        <div class="progress-bar-fill" id="progress-${app.name}"></div>
                    </div>
                    <div class="progress-info">
                        <span id="stage-${app.name}">Preparing...</span>
                        <span id="percent-${app.name}">0%</span>
                    </div>
                    <div class="progress-info" style="margin-top: 4px;">
                        <span id="speed-${app.name}"></span>
                        <span id="bytes-${app.name}"></span>
                    </div>
                </div>
            </div>
        ` + "`" + `;
    }

    html += '</div>';
    container.innerHTML = html;
}

async function startDownload(name) {
    const card = document.getElementById('card-' + name);
    if (!card) return;

    try {
        const response = await fetch('/api/store/download/' + encodeURIComponent(name), {
            method: 'POST'
        });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to start download');
        }

        // Show progress UI
        card.classList.add('downloading');
        activeDownloads[name] = data.key;

        // Start polling for progress
        pollProgress(name, data.key);

    } catch (error) {
        alert('Failed to start download: ' + error.message);
    }
}

async function pollProgress(name, key) {
    try {
        const response = await fetch('/api/store/progress/' + encodeURIComponent(key));
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get progress');
        }

        updateProgress(name, data);

        // Continue polling if download is still active
        if (data.status === 'downloading' || data.status === 'verifying' || data.status === 'merging' || data.status === 'pending') {
            setTimeout(() => pollProgress(name, key), 500);
        } else if (data.status === 'completed') {
            // Download completed
            delete activeDownloads[name];
            const card = document.getElementById('card-' + name);
            if (card) {
                const btn = card.querySelector('.btn-download');
                if (btn) {
                    btn.innerHTML = '<span class="material-icons">check</span> Downloaded';
                    btn.classList.add('completed');
                    btn.disabled = true;
                }
                card.classList.remove('downloading');
            }
            // Optionally redirect to appliances page or show success message
            showNotification('Download completed: ' + name, 'success');
        } else if (data.status === 'error') {
            // Download failed
            delete activeDownloads[name];
            const card = document.getElementById('card-' + name);
            if (card) {
                card.classList.remove('downloading');
            }
            alert('Download failed: ' + (data.error || 'Unknown error'));
        }

    } catch (error) {
        console.error('Error polling progress:', error);
        // Retry after a delay
        setTimeout(() => pollProgress(name, key), 2000);
    }
}

function updateProgress(name, data) {
    const progressBar = document.getElementById('progress-' + name);
    const stage = document.getElementById('stage-' + name);
    const percent = document.getElementById('percent-' + name);
    const speed = document.getElementById('speed-' + name);
    const bytes = document.getElementById('bytes-' + name);

    if (progressBar) {
        progressBar.style.width = Math.min(data.percent || 0, 100) + '%%';
    }

    if (stage) {
        stage.textContent = data.stage || data.status || 'Processing...';
    }

    if (percent) {
        percent.textContent = (data.percent || 0).toFixed(1) + '%%';
    }

    if (speed && data.speed) {
        speed.textContent = formatBytes(data.speed) + '/s';
    }

    if (bytes && data.bytes_downloaded && data.total_bytes) {
        bytes.textContent = formatBytes(data.bytes_downloaded) + ' / ' + formatBytes(data.total_bytes);
    }
}

async function refreshCatalog() {
    try {
        const response = await fetch('/api/store/refresh', {
            method: 'POST'
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to refresh');
        }

        showNotification('Catalog refresh initiated', 'info');

        // Reload after a short delay to allow refresh to complete
        setTimeout(loadStore, 2000);

    } catch (error) {
        alert('Failed to refresh catalog: ' + error.message);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(message, type) {
    // Simple notification - can be enhanced
    console.log('[' + type + '] ' + message);

    // Create toast notification
    const toast = document.createElement('div');
    toast.style.cssText = 'position: fixed; bottom: 20px; right: 20px; padding: 12px 24px; border-radius: 4px; color: white; z-index: 10000; animation: slideIn 0.3s ease;';
    toast.style.background = type === 'success' ? 'var(--success)' : type === 'error' ? 'var(--danger)' : 'var(--primary)';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Load store on page load
loadStore();
</script>
`
}
