package webconsole

import (
	"fmt"
	"net/http"
	"strings"
	"time"

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
	wc.mux.HandleFunc("/", wc.handlePage)
	wc.mux.HandleFunc("/login", wc.handleLoginPage)
	wc.mux.HandleFunc("/logout", wc.handleLogout)
	wc.mux.HandleFunc("/dashboard", wc.requireAuth(wc.handleDashboard))
	wc.mux.HandleFunc("/vms", wc.requireAuth(wc.handleVMsPage))
	wc.mux.HandleFunc("/vms/", wc.requireAuth(wc.handleVMDetailPage))
	wc.mux.HandleFunc("/console/", wc.requireAuth(wc.handleConsolePage))
	wc.mux.HandleFunc("/networks", wc.requireAuth(wc.handleNetworksPage))
	wc.mux.HandleFunc("/images", wc.requireAuth(wc.handleImagesPage))
	wc.mux.HandleFunc("/logs", wc.requireAuth(wc.handleLogsPage))
	wc.mux.HandleFunc("/settings", wc.requireAuth(wc.handleSettingsPage))
	wc.mux.HandleFunc("/users", wc.requireAdmin(wc.handleUsersPage))
	wc.mux.HandleFunc("/groups", wc.requireAdmin(wc.handleGroupsPage))
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - FireCrackManager</title>
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header .material-icons {
            font-size: 48px;
            color: #1976d2;
        }
        .login-header h1 {
            color: #333;
            font-size: 24px;
            margin-top: 10px;
        }
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #1976d2;
        }
        .btn {
            width: 100%;
            padding: 14px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: #1565c0; }
        .error {
            background: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <span class="material-icons">local_fire_department</span>
            <h1>FireCrackManager</h1>
            <p>MicroVM Management Console</p>
        </div>
        <div class="error" id="error"></div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
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
        });
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

	adminMenu := ""
	if isAdmin {
		adminMenu = `<a href="/users" class="nav-item" data-page="users">
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
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        :root {
            --primary: #1976d2;
            --primary-dark: #1565c0;
            --success: #4caf50;
            --danger: #f44336;
            --warning: #ff9800;
            --sidebar-bg: #263238;
            --sidebar-hover: #37474f;
            --text-primary: #333;
            --text-secondary: #666;
            --border-color: #e0e0e0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            min-height: 100vh;
            display: flex;
        }
        .sidebar {
            width: 240px;
            background: var(--sidebar-bg);
            color: white;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }
        .sidebar-header {
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .sidebar-header .material-icons {
            color: #ff5722;
            font-size: 32px;
        }
        .sidebar-header h1 {
            font-size: 18px;
            font-weight: 500;
        }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 20px;
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            transition: all 0.2s;
        }
        .nav-item:hover, .nav-item.active {
            background: var(--sidebar-hover);
            color: white;
        }
        .nav-item.active {
            border-left: 3px solid var(--primary);
        }
        .nav-item .material-icons {
            font-size: 20px;
        }
        .main-content {
            flex: 1;
            margin-left: 240px;
            min-height: 100vh;
        }
        .topbar {
            background: white;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .topbar h2 {
            color: var(--text-primary);
            font-size: 24px;
            font-weight: 500;
        }
        .user-menu {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .user-menu span {
            color: var(--text-secondary);
        }
        .user-menu a {
            color: var(--danger);
            text-decoration: none;
        }
        .content {
            padding: 30px;
        }
        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        .card-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-header h3 {
            font-size: 18px;
            font-weight: 500;
            color: var(--text-primary);
        }
        .card-body {
            padding: 20px;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 10px 16px;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-dark); }
        .btn-success { background: var(--success); color: white; }
        .btn-success:hover { background: #43a047; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover { background: #e53935; }
        .btn-secondary { background: #757575; color: white; }
        .btn-secondary:hover { background: #616161; }
        .btn-sm { padding: 4px 8px; font-size: 11px; }
        .btn-sm .material-icons { font-size: 16px; }
        .btn-xs { padding: 2px 6px; font-size: 10px; }
        .btn-xs .material-icons { font-size: 14px; }
        .btn .material-icons { font-size: 18px; }
        .action-menu {
            position: relative;
            display: inline-block;
        }
        .action-menu-btn {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .action-dropdown {
            display: none;
            position: absolute;
            right: 0;
            top: 100%%;
            min-width: 180px;
            background: white;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            overflow: hidden;
        }
        .action-dropdown.show {
            display: block;
        }
        .action-dropdown-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            cursor: pointer;
            transition: background 0.15s;
            font-size: 13px;
            color: var(--text-primary);
            border: none;
            background: none;
            width: 100%%;
            text-align: left;
        }
        .action-dropdown-item:hover {
            background: var(--bg-secondary);
        }
        .action-dropdown-item:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .action-dropdown-item:disabled:hover {
            background: none;
        }
        .action-dropdown-item .material-icons {
            font-size: 18px;
            color: var(--text-secondary);
        }
        .action-dropdown-item.danger {
            color: var(--danger);
        }
        .action-dropdown-item.danger .material-icons {
            color: var(--danger);
        }
        .action-dropdown-item.success {
            color: var(--success);
        }
        .action-dropdown-item.success .material-icons {
            color: var(--success);
        }
        .action-dropdown-divider {
            height: 1px;
            background: var(--border-color);
            margin: 4px 0;
        }
        table {
            width: 100%%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background: #fafafa;
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 13px;
            text-transform: uppercase;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        .badge-success { background: #e8f5e9; color: #2e7d32; }
        .badge-danger { background: #ffebee; color: #c62828; }
        .badge-warning { background: #fff3e0; color: #ef6c00; }
        .badge-info { background: #e3f2fd; color: #1565c0; }
        .stat-card {
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .stat-icon {
            width: 50px;
            height: 50px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .stat-icon .material-icons {
            color: white;
            font-size: 24px;
        }
        .stat-info h4 {
            font-size: 28px;
            font-weight: 600;
            color: var(--text-primary);
        }
        .stat-info p {
            color: var(--text-secondary);
            font-size: 14px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-weight: 500;
            color: var(--text-primary);
        }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%%;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 14px;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--primary);
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: white;
            border-radius: 8px;
            max-width: 500px;
            width: 90%%;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 { font-size: 18px; }
        .modal-close {
            cursor: pointer;
            color: var(--text-secondary);
        }
        .modal-body { padding: 20px; }
        .modal-footer {
            padding: 15px 20px;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .alert {
            padding: 12px 16px;
            border-radius: 4px;
            margin-bottom: 16px;
        }
        .alert-success { background: #e8f5e9; color: #2e7d32; }
        .alert-danger { background: #ffebee; color: #c62828; }
        .progress-bar {
            height: 4px;
            background: var(--border-color);
            border-radius: 2px;
            overflow: hidden;
        }
        .progress-bar-fill {
            height: 100%%;
            background: var(--primary);
            transition: width 0.3s;
        }
        .actions { display: flex; gap: 8px; }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }
        .empty-state .material-icons {
            font-size: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
    </style>
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
            <a href="/logs" class="nav-item" data-page="logs">
                <span class="material-icons">article</span>
                <span>Logs</span>
            </a>
            <a href="/settings" class="nav-item" data-page="settings">
                <span class="material-icons">settings</span>
                <span>Settings</span>
            </a>
            %s
        </nav>
    </aside>
    <main class="main-content">
        <header class="topbar">
            <h2>%s</h2>
            <div class="user-menu">
                <span>%s</span>
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
</html>`, title, adminMenu, title, username, content, page)
}

func (wc *WebConsole) renderDashboard() string {
	return `
<div class="grid">
    <div class="card stat-card">
        <div class="stat-icon" style="background: #1976d2;">
            <span class="material-icons">memory</span>
        </div>
        <div class="stat-info">
            <h4 id="vmCount">-</h4>
            <p>Virtual Machines</p>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="background: #4caf50;">
            <span class="material-icons">play_circle</span>
        </div>
        <div class="stat-info">
            <h4 id="runningCount">-</h4>
            <p>Running VMs</p>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="background: #ff9800;">
            <span class="material-icons">hub</span>
        </div>
        <div class="stat-info">
            <h4 id="networkCount">-</h4>
            <p>Networks</p>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="background: #9c27b0;">
            <span class="material-icons">storage</span>
        </div>
        <div class="stat-info">
            <h4 id="imageCount">-</h4>
            <p>Images</p>
        </div>
    </div>
</div>

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
async function loadDashboard() {
    const { ok, data } = await apiCall('/api/stats');
    if (ok) {
        document.getElementById('vmCount').textContent = data.vms?.total || 0;
        document.getElementById('runningCount').textContent = data.vms?.running || 0;
        document.getElementById('networkCount').textContent = data.networks?.total || 0;
        document.getElementById('imageCount').textContent = (data.kernels || 0) + (data.rootfs || 0);
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
loadDashboard();
setInterval(loadDashboard, 10000);
</script>
`
}

func (wc *WebConsole) renderVMsPage() string {
	return `
<div class="card">
    <div class="card-header">
        <h3>Virtual Machines</h3>
        <div style="display: flex; gap: 8px;">
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
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>vCPU</th>
                    <th>Memory</th>
                    <th>Status</th>
                    <th>IP Address</th>
                    <th>Reachable</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="vmList">
                <tr><td colspan="7">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

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
                    <input type="text" name="kernel_args" placeholder="console=ttyS0 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" placeholder="8.8.8.8,8.8.4.4">
                    <small style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
                </div>
                <div class="form-group">
                    <label>Snapshot Type (optional)</label>
                    <select name="snapshot_type" id="snapshotTypeSelect">
                        <option value="">Disabled</option>
                        <option value="Full">Full Snapshot</option>
                        <option value="Diff">Differential Snapshot</option>
                    </select>
                    <small style="color: var(--text-secondary); font-size: 11px;">Enable Firecracker snapshot feature for VM state preservation.</small>
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
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" id="editVmDnsServers" placeholder="8.8.8.8,8.8.4.4">
                    <small style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
                </div>
                <div class="form-group">
                    <label>Snapshot Type (optional)</label>
                    <select name="snapshot_type" id="editVmSnapshotType">
                        <option value="">Disabled</option>
                        <option value="Full">Full Snapshot</option>
                        <option value="Diff">Differential Snapshot</option>
                    </select>
                    <small style="color: var(--text-secondary); font-size: 11px;">Enable Firecracker snapshot feature for VM state preservation.</small>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="editVmAutorun" style="width: auto; margin-right: 8px;">
                        Autorun
                    </label>
                    <small style="color: var(--text-secondary); font-size: 11px;">Start this VM automatically when FireCrackManager starts.</small>
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
                <small style="color: var(--text-secondary); font-size: 11px;">Select a .fcrack virtual appliance file to import.</small>
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
            <span class="material-icons modal-close" onclick="closeModal('duplicateVMModal')">close</span>
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
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('duplicateVMModal')">Cancel</button>
                <button type="submit" class="btn btn-primary">Duplicate</button>
            </div>
        </form>
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

<script>
let openMenuVmId = null;

async function loadVMs() {
    // Skip refresh if action menu is open
    if (openMenuVmId !== null) {
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
                        <button class="action-dropdown-item" onclick="createSnapshot('${vm.id}'); closeAllMenus();" ${vm.status !== 'running' || !vm.snapshot_type ? 'disabled' : ''}>
                            <span class="material-icons">photo_camera</span> Snapshots
                        </button>
                        <button class="action-dropdown-item" onclick="openDisksModal('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">storage</span> Disks
                        </button>
                        <div class="action-dropdown-divider"></div>
                        <button class="action-dropdown-item" onclick="duplicateVM('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">content_copy</span> Duplicate
                        </button>
                        <button class="action-dropdown-item" onclick="exportVM('${vm.id}', '${vm.name}'); closeAllMenus();" ${vm.status === 'running' ? 'disabled' : ''}>
                            <span class="material-icons">download</span> Export
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
                cell.innerHTML = '<span class="material-icons" style="color: var(--success);" title="Reachable">check_circle</span>';
            } else {
                cell.innerHTML = '<span class="material-icons" style="color: var(--danger);" title="Unreachable">cancel</span>';
            }
        } else {
            cell.innerHTML = '<span class="material-icons" style="color: var(--text-secondary);" title="Unknown">help_outline</span>';
        }
    } catch (e) {
        cell.innerHTML = '<span class="material-icons" style="color: var(--text-secondary);" title="Error">help_outline</span>';
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
        const select = document.getElementById('rootfsSelect');
        rootfs.data.rootfs.forEach(r => {
            select.innerHTML += ` + "`" + `<option value="${r.id}">${r.name}</option>` + "`" + `;
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
        snapshot_type: formData.get('snapshot_type') || ''
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

async function submitDuplicateVM(event) {
    event.preventDefault();
    const vmId = document.getElementById('duplicateVmId').value;
    const name = document.getElementById('duplicateVmName').value;

    const { ok, data } = await apiCall(` + "`" + `/api/vms/${vmId}/duplicate` + "`" + `, 'POST', { name });
    if (ok) {
        closeModal('duplicateVMModal');
        loadVMs();
        alert('VM duplicated successfully!');
    } else {
        alert(data.error || 'Failed to duplicate VM');
    }
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

loadVMs();
loadFormData();
setInterval(loadVMs, 5000);
</script>
`
}

func (wc *WebConsole) renderVMDetailPage(vmID string) string {
	return fmt.Sprintf(`
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
            <button class="btn btn-secondary" onclick="deleteVM()">
                <span class="material-icons">delete</span> Delete
            </button>
        </div>
    </div>
    <div class="card-body">
        <div class="grid">
            <div>
                <p><strong>Name:</strong> <span id="vmName">-</span></p>
                <p><strong>ID:</strong> <span id="vmId">%s</span></p>
                <p><strong>Status:</strong> <span id="vmStatus">-</span></p>
                <p><strong>PID:</strong> <span id="vmPid">-</span></p>
            </div>
            <div>
                <p><strong>vCPUs:</strong> <span id="vmVcpu">-</span></p>
                <p><strong>Memory:</strong> <span id="vmMemory">-</span> MB</p>
                <p><strong>IP Address:</strong> <span id="vmIp">-</span> <span id="vmReachable"></span></p>
                <p><strong>MAC Address:</strong> <span id="vmMac">-</span></p>
                <p><strong>DNS Servers:</strong> <span id="vmDns">-</span></p>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h3>VM Logs</h3>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Level</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody id="vmLogs">
                <tr><td colspan="3">Loading...</td></tr>
            </tbody>
        </table>
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

async function loadVMLogs() {
    const { ok, data } = await apiCall('/api/logs/' + vmId + '?limit=50');
    if (!ok) return;

    const tbody = document.getElementById('vmLogs');
    if (!data.logs || data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3">No logs</td></tr>';
        return;
    }

    tbody.innerHTML = data.logs.map(log => ` + "`" + `
        <tr>
            <td>${formatDate(log.created_at)}</td>
            <td><span class="badge badge-${log.level === 'error' ? 'danger' : log.level === 'warning' ? 'warning' : 'info'}">${log.level}</span></td>
            <td>${log.message}</td>
        </tr>
    ` + "`" + `).join('');
}

async function startVM() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/start', 'POST');
    if (ok) {
        loadVMDetails();
        loadVMLogs();
    } else {
        alert(data.error || 'Failed to start VM');
    }
}

async function stopVM() {
    const { ok, data } = await apiCall('/api/vms/' + vmId + '/stop', 'POST');
    if (ok) {
        loadVMDetails();
        loadVMLogs();
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
            networkSelect.innerHTML += ` + "`" + `<option value="${n.id}" ${selected}>${n.name} (${n.subnet})</option>` + "`" + `;
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

loadVMDetails();
loadVMLogs();
setInterval(loadVMDetails, 5000);
setInterval(loadVMLogs, 10000);
</script>

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
                    <input type="text" name="kernel_args" id="editVmKernelArgs" placeholder="console=ttyS0 reboot=k panic=1 pci=off">
                </div>
                <div class="form-group">
                    <label>DNS Servers (optional)</label>
                    <input type="text" name="dns_servers" id="editVmDnsServers" placeholder="8.8.8.8,8.8.4.4">
                    <small style="color: var(--text-secondary); font-size: 11px;">Comma-separated DNS server IPs. Applied to /etc/resolv.conf on VM start.</small>
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
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>

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
</script>
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
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="networkList">
                <tr><td colspan="7">Loading...</td></tr>
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
                    <label>
                        <input type="checkbox" name="enable_nat" checked> Enable NAT
                    </label>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal('createNetworkModal')">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="createNetwork()">Create</button>
        </div>
    </div>
</div>

<script>
async function loadNetworks() {
    const { ok, data } = await apiCall('/api/networks');
    if (!ok) return;

    const tbody = document.getElementById('networkList');
    if (!data.networks || data.networks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><span class="material-icons">hub</span><p>No networks</p></td></tr>';
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
            <td class="actions">
                ${net.status === 'inactive'
                    ? ` + "`" + `<button class="btn btn-success btn-sm" onclick="activateNetwork('${net.id}')"><span class="material-icons">power</span></button>` + "`" + `
                    : ` + "`" + `<button class="btn btn-warning btn-sm" onclick="deactivateNetwork('${net.id}')"><span class="material-icons">power_off</span></button>` + "`" + `
                }
                <button class="btn btn-secondary btn-sm" onclick="deleteNetwork('${net.id}')" ${net.status === 'active' ? 'disabled' : ''}>
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
}

async function createNetwork() {
    const form = document.getElementById('createNetworkForm');
    const formData = new FormData(form);
    const data = {
        name: formData.get('name'),
        subnet: formData.get('subnet'),
        gateway: formData.get('gateway') || '',
        enable_nat: formData.get('enable_nat') === 'on'
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
        </div>
    </div>
    <div class="card-body">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Format</th>
                    <th>Size</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="rootfsList">
                <tr><td colspan="4">Loading...</td></tr>
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
                    <small style="color: var(--text-secondary); font-size: 11px;">Supported formats: ext4, img, raw. Large files are supported.</small>
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
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><span class="material-icons">storage</span><p>No root filesystems</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.rootfs.map(r => ` + "`" + `
        <tr>
            <td>${r.name}</td>
            <td>${r.format}</td>
            <td>${formatBytes(r.size)}</td>
            <td class="actions">
                <button class="btn btn-secondary btn-xs" onclick="openDuplicateRootfsModal('${r.id}', '${r.name}')" title="Duplicate">
                    <span class="material-icons">content_copy</span>
                </button>
                <button class="btn btn-secondary btn-xs" onclick="openRenameRootfsModal('${r.id}', '${r.name}')" title="Rename">
                    <span class="material-icons">edit</span>
                </button>
                <button class="btn btn-danger btn-xs" onclick="deleteRootfs('${r.id}')" title="Delete">
                    <span class="material-icons">delete</span>
                </button>
            </td>
        </tr>
    ` + "`" + `).join('');
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

loadKernels();
loadRootfs();
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
                    <th>Time</th>
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
            <td>${formatDate(log.created_at)}</td>
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
            <tr><td><strong>Config File:</strong></td><td>/etc/firecrackmanager/settings.json</td></tr>
            <tr><td><strong>Data Directory:</strong></td><td>/var/lib/firecrackmanager</td></tr>
            <tr><td><strong>Log File:</strong></td><td>/var/log/firecrackmanager/firecrackmanager.log</td></tr>
            <tr><td><strong>Firecracker Binary:</strong></td><td>/usr/sbin/firecracker</td></tr>
        </table>
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

// Load system status immediately (fast)
loadSystemStatus();
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
                    <small style="color: var(--text-secondary); font-size: 11px;">Select which operations group members can perform on assigned VMs.</small>
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
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #2d2d2d;
            padding: 10px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #404040;
        }
        .header-left {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header h1 {
            font-size: 16px;
            font-weight: 500;
        }
        .header .material-icons {
            color: #ff5722;
            font-size: 24px;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%%;
            background: #666;
        }
        .status-dot.connected { background: #4caf50; }
        .status-dot.disconnected { background: #f44336; }
        .status-dot.connecting { background: #ff9800; animation: pulse 1s infinite; }
        @keyframes pulse {
            0%%, 100%% { opacity: 1; }
            50%% { opacity: 0.5; }
        }
        .btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .btn .material-icons { font-size: 16px; }
        .btn-secondary {
            background: #404040;
            color: #d4d4d4;
        }
        .btn-secondary:hover { background: #505050; }
        .btn-danger {
            background: #d32f2f;
            color: white;
        }
        .btn-danger:hover { background: #c62828; }
        #terminal-container {
            flex: 1;
            padding: 10px;
            overflow: hidden;
        }
        #terminal {
            width: 100%%;
            height: 100%%;
        }
        .vm-info {
            font-size: 12px;
            color: #888;
        }
    </style>
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

    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
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
