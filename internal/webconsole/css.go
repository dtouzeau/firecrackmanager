package webconsole

// LoginPageCSS contains styles for the login page (Artica-style)
const LoginPageCSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: Arial, "MS UI Gothic", "MS P Gothic", sans-serif;
    background-image: url('/assets/Articafond3.png');
    background-color: #283437;
    background-size: 1280px 1076px;
    background-position: center 0%%;
    background-repeat: no-repeat;
    min-height: 100vh;
}
.wrapper {
    background-color: #283437;
    min-height: 100vh;
}
.main-container {
    display: table;
    margin: 100px auto 0;
}
.title-row {
    display: table-row;
}
.title-name {
    font-size: 40pt;
    color: #ffffff;
    display: flex;
    align-items: center;
    gap: 20px;
}
.title-name .material-icons {
    font-size: 48px;
    color: #ff5722;
}
.subtitle {
    font-size: 26pt;
    color: #a7b1c2;
    margin-left: 68px;
    margin-top: 10px;
}
.description {
    font-size: 11pt;
    color: #ffffff;
    width: 480px;
    margin: 20px 0 0 68px;
    line-height: 1.5;
}
.form-input {
    display: block;
    background-color: rgba(255,255,255,0.2);
    border-radius: 4px;
    padding: 23px 22px;
    width: 480px;
    border: 0;
    height: 30px;
    color: #ffffff;
    font-size: 28px;
    font-weight: bold;
    margin: 20px 0 0 68px;
}
.form-input::placeholder {
    color: rgba(255,255,255,0.6);
    font-weight: normal;
}
.form-input:focus {
    outline: none;
    background-color: rgba(255,255,255,0.3);
}
.login-button {
    background-color: #18a689;
    border-radius: 4px;
    transition: background-color 0.2s;
    height: 68px;
    width: 300px;
    font-size: 28pt;
    color: #fff;
    text-align: center;
    margin: 50px 0 0 68px;
    line-height: 68px;
    cursor: pointer;
    border: none;
}
.login-button:hover {
    background-color: #1ab394;
}
.error-hint {
    color: rgb(255, 204, 0);
    margin: 10px 0 -10px 68px;
    font-size: 18px;
    display: none;
}
.version-info {
    margin-top: 20px;
    font-size: x-small;
    color: #ffffff;
    text-align: right;
    margin-left: 68px;
    width: 480px;
}

/* Mobile responsive */
@media screen and (max-width: 1000px) {
    .main-container {
        width: 90%%;
        margin: 30px auto 0;
    }
    .title-name {
        font-size: 20pt;
    }
    .title-name .material-icons {
        font-size: 32px;
    }
    .subtitle {
        font-size: 13pt;
        margin-left: 15px;
    }
    .description {
        font-size: 12pt;
        width: 100%%;
        margin-left: 15px;
    }
    .form-input {
        padding: 10px 11px;
        width: 100%%;
        height: 30px;
        font-size: 16px;
        margin-left: 15px;
    }
    .login-button {
        height: 50px;
        width: 100%%;
        font-size: 14pt;
        margin: 25px 0 40px 15px;
        line-height: 50px;
    }
    .error-hint {
        margin-left: 15px;
    }
    .version-info {
        margin-left: 15px;
        width: 100%%;
    }
}
`

// MainLayoutCSS contains the main application CSS with variables and common components
const MainLayoutCSS = `
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
    --text-muted: #999;
    --border-color: #e0e0e0;
    --border: #e0e0e0;
    --bg-secondary: #f5f5f5;
    --card-bg: #ffffff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f5f5;
    min-height: 100vh;
    display: flex;
}

/* Sidebar */
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
    gap: 6px;
    padding: 5px 9px;
    color: rgba(255,255,255,0.7);
    text-decoration: none;
	font-size:12px;
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
    font-size: 15px;
}

/* Main Content */
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
.user-menu .user-link {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-secondary);
    padding: 6px 10px;
    border-radius: 6px;
    transition: all 0.2s;
}
.user-menu .user-link:hover {
    background: var(--bg-secondary);
    color: var(--primary);
}
.user-menu .user-link .material-icons {
    font-size: 20px;
}
.content {
    padding: 30px;
}

/* Cards */
.card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
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

/* Buttons - Artica style */
.btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border: 1px solid transparent;
    border-radius: 3px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.15s ease-in-out;
    outline: none;
}
.btn:hover {
    opacity: 0.9;
}
.btn:focus {
    outline: none !important;
}
.btn:active {
    box-shadow: inset 0 2px 4px rgba(0,0,0,0.15);
}

/* Primary button - Artica green */
.btn-primary {
    background-color: #1ab394;
    border-color: #1ab394;
    color: #FFFFFF;
}
.btn-primary:hover,
.btn-primary:focus,
.btn-primary:active {
    background-color: #18a689;
    border-color: #18a689;
    color: #FFFFFF;
}

/* Success button - Same as primary in Artica */
.btn-success {
    background-color: #1ab394;
    border-color: #1ab394;
    color: #FFFFFF;
}
.btn-success:hover,
.btn-success:focus,
.btn-success:active {
    background-color: #005447;
    border-color: #005447;
    color: #FFFFFF;
}

/* Info button - Artica blue */
.btn-info {
    background-color: #23c6c8;
    border-color: #23c6c8;
    color: #FFFFFF;
}
.btn-info:hover,
.btn-info:focus,
.btn-info:active {
    background-color: #21b9bb;
    border-color: #21b9bb;
    color: #FFFFFF;
}

/* Warning button - Artica orange */
.btn-warning {
    background-color: #f8ac59;
    border-color: #f8ac59;
    color: #FFFFFF;
}
.btn-warning:hover,
.btn-warning:focus,
.btn-warning:active {
    background-color: #f7a54a;
    border-color: #f7a54a;
    color: #FFFFFF;
}

/* Danger button - Artica red */
.btn-danger {
    background-color: #ed5565;
    border-color: #ed5565;
    color: #FFFFFF;
}
.btn-danger:hover,
.btn-danger:focus,
.btn-danger:active {
    background-color: #ec4758;
    border-color: #ec4758;
    color: #FFFFFF;
}

/* Default/Secondary button */
.btn-default,
.btn-secondary {
    color: inherit;
    background: white;
    border: 1px solid #e7eaec;
}
.btn-default:hover,
.btn-default:focus,
.btn-default:active,
.btn-secondary:hover,
.btn-secondary:focus,
.btn-secondary:active {
    color: inherit;
    border: 1px solid #d2d2d2;
    background: #f8f8f8;
}

/* Blue button */
.btn-blue {
    background-color: #1c84c6;
    border-color: #1c84c6;
    color: #FFFFFF;
}
.btn-blue:hover,
.btn-blue:focus,
.btn-blue:active {
    background-color: #1a7bb9;
    border-color: #1a7bb9;
    color: #FFFFFF;
}

/* Button sizes */
.btn-lg { padding: 10px 20px; font-size: 15px; }
.btn-sm { padding: 5px 10px; font-size: 12px; }
.btn-xs { padding: 3px 8px; font-size: 11px; }
.btn .material-icons { font-size: 16px; }
.btn-sm .material-icons { font-size: 14px; }
.btn-xs .material-icons { font-size: 12px; }

/* Disabled state */
.btn:disabled,
.btn.disabled {
    opacity: 0.65;
    cursor: not-allowed;
    pointer-events: none;
}

/* Outline buttons */
.btn-outline {
    background: transparent;
}
.btn-primary.btn-outline { color: #1ab394; border-color: #1ab394; }
.btn-primary.btn-outline:hover { background-color: #1ab394; color: #fff; }
.btn-success.btn-outline { color: #1ab394; border-color: #1ab394; }
.btn-success.btn-outline:hover { background-color: #1ab394; color: #fff; }
.btn-info.btn-outline { color: #23c6c8; border-color: #23c6c8; }
.btn-info.btn-outline:hover { background-color: #23c6c8; color: #fff; }
.btn-warning.btn-outline { color: #f8ac59; border-color: #f8ac59; }
.btn-warning.btn-outline:hover { background-color: #f8ac59; color: #fff; }
.btn-danger.btn-outline { color: #ed5565; border-color: #ed5565; }
.btn-danger.btn-outline:hover { background-color: #ed5565; color: #fff; }

/* Action Menu Dropdown */
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
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15);
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

/* Dropdown Menu (for images/rootfs page) */
.dropdown {
    position: relative;
    display: inline-block;
}
.dropdown-toggle {
    cursor: pointer;
}
.dropdown-menu {
    display: none;
    position: absolute;
    right: 0;
    top: 100%%;
    min-width: 160px;
    background: white;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 1000;
    overflow: hidden;
}
.dropdown-menu.show {
    display: block;
}
.dropdown-menu a {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    color: var(--text-primary);
    text-decoration: none;
    font-size: 13px;
    transition: background 0.15s;
}
.dropdown-menu a:hover {
    background: var(--bg-secondary);
}
.dropdown-menu a .material-icons {
    font-size: 18px;
    color: var(--text-secondary);
}
.dropdown-menu a.danger {
    color: var(--danger);
}
.dropdown-menu a.danger .material-icons {
    color: var(--danger);
}
.dropdown-menu a.disabled {
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
}
.dropdown-divider {
    height: 1px;
    background: var(--border-color);
    margin: 4px 0;
}

/* Tables */
table {
    width: 100%%;
    border-collapse: collapse;
}
th, td {
    padding: 5px;
    text-align: left;
    font-size: 12px;
    border-bottom: 1px solid var(--border-color);
}
th {
    background: #fafafa;
    font-weight: 500;
    color: var(--text-secondary);
    font-size: 14px;
    text-transform: uppercase;
}

/* Badges */
.badge {
    display: inline-block !important;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 500;
	display: ruby;
	min-width: 54px;
}
.badge-success { background: #1ab394; color: #FFFFFF; border:1px solid #e8f5e9; }
.badge-danger { background: #dc3545; color: #FFFFFF; border:1px solid #ffebee; }
.badge-warning { background: #f8ac59 ; color:#FFFFFF; border:1px solid #fff3e0; }
.badge-info { background: #1565c0; color: #e3f2fd;border:1px solid #e3f2fd; }
.badge-secondary { background: #d1dade; color: #5e5e5e;font-weight: 600;border:1px solid #5e5e5e; }
a.badge.badge-success { color: white; }
.rfs-description { font-size: 10px; color: var(--text-secondary); margin-top: 2px; text-transform: capitalize; font-style: italic; }
.permission-list { list-style: none; margin: 0; padding: 0; font-size: 12px; }
.permission-list li { padding: 2px 0; text-transform: capitalize; }

/* Stats Cards (legacy) */
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

/* Artica-style ibox widgets */
.ibox {
    background: white;
    border-radius: 4px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
.ibox-title {
    background: #f5f5f5;
    border-bottom: 1px solid #e7eaec;
    padding: 12px 15px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.ibox-title h5 {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
}
.ibox-title .label {
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 3px;
    font-weight: 600;
}
.ibox-title .label-primary {
    background: #1ab394;
    color: white;
}
.ibox-title .label-success {
    background: #1ab394;
    color: white;
}
.ibox-title .label-warning {
    background: #f8ac59;
    color: white;
}
.ibox-title .label-danger {
    background: #ed5565;
    color: white;
}
.ibox-content {
    padding: 15px;
}
.ibox-content h1 {
    font-size: 32px;
    font-weight: 400;
    color: var(--text-primary);
    margin: 0 0 5px 0;
}
.ibox-content .stat-percent {
    font-size: 12px;
}
.ibox-content .stat-percent.text-success {
    color: #1ab394;
}
.ibox-content .stat-percent.text-warning {
    color: #f8ac59;
}
.ibox-content .stat-percent.text-danger {
    color: #ed5565;
}
.ibox-content small {
    color: var(--text-secondary);
    font-size: 12px;
}
.ibox-footer {
    padding: 10px 15px;
    background: #fafafa;
    border-top: 1px solid #e7eaec;
}
.ibox-footer canvas {
    width: 100%% !important;
    height: 40px !important;
}

/* Dashboard grid for ibox */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin-bottom: 20px;
}
@media (max-width: 1200px) {
    .dashboard-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
}

/* Grid */
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
	font-size: 14px;
    gap: 20px;
}
.grid strong {
    font-size: 12px;
    font-weight: 500;
}
.small-text-tip{
	padding-right: 5px;
	padding-left:5px;

}
/* Forms */
.form-group {
    margin-bottom: 16px;
	margin-left:5px;
	margin-right:5px;
}
.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    font-size: 13px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.form-group input, .form-group select, .form-group textarea {
    width: 100%%;
    padding: 12px 14px;
    border: 2px solid #e8e8e8;
    border-radius: 10px;
    font-size: 14px;
    background: #fafafa;
    transition: all 0.2s ease;
}
.form-group input:hover, .form-group select:hover, .form-group textarea:hover {
    border-color: #d0d0d0;
    background: #f5f5f5;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none;
    border-color: var(--primary);
    background: white;
    box-shadow: 0 0 0 4px rgba(25, 118, 210, 0.1);
}
.form-group input::placeholder {
    color: #aaa;
}
.form-group input:disabled, .form-group select:disabled {
    background: #f0f0f0;
    color: #888;
    cursor: not-allowed;
}
.form-group small {
    display: block;
    margin-top: 6px;
    font-size: 12px;
    color: var(--text-secondary);
}

/* Modals */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0);
    backdrop-filter: blur(0px);
    z-index: 1000;
    align-items: center;
    justify-content: center;
    transition: background 0.3s ease, backdrop-filter 0.3s ease;
}
.modal.active {
    display: flex;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(4px);
}
.modal-content {
    background: white;
    border-radius: 16px;
    max-width: 500px;
    width: 90%%;
    max-height: 85vh;
    overflow: hidden;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.05);
    transform: scale(0.95) translateY(10px);
    opacity: 0;
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.3s ease;
}
.modal.active .modal-content {
    transform: scale(1) translateY(0);
    opacity: 1;
}
.modal-content form {
    padding-left: 10px;
    padding-right: 10px;
}
.form-actions {
    text-align: right;
    margin-top: 10px;
    border-top: 1px solid #CCCCCC;
    padding-top: 5px;
}
table.data-table {
    margin-left: 10px;
    width: 97%%;
}
.page-header {
    margin-bottom: 5px;
}
.card-body p {
    font-size: 14px;
}
tbody a {
    color: #464646;
    text-decoration: none;
}
tbody a:visited {
    color: #464646;
}
tbody a:hover {
    font-weight: 700;
    color: black;
    text-decoration: none;
}
td.actions {
    vertical-align: middle;
}
.export-progress {
    margin-top: 4px;
    margin-left: 24px;
}
.export-progress-text {
    font-size: 11px;
    color: var(--primary);
    margin-bottom: 2px;
    display: flex;
    align-items: center;
    gap: 4px;
}
.export-progress-bar {
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
    width: 200px;
}
.export-progress-fill {
    height: 100%%;
    background: var(--primary);
    border-radius: 2px;
    transition: width 0.3s ease;
}
.modal-header {
    padding: 7px 8px 8px;
    background: linear-gradient(135deg, var(--primary) 0%%,var(--primary-dark) 100%%);
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.modal-header h2, .modal-header h3 {
    font-size: 18px;
    font-weight: 600;
    color: white;
    margin: 0;
    letter-spacing: -0.01em;
}
.modal-close {
    cursor: pointer;
    color: rgba(255, 255, 255, 0.8);
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 8px;
    transition: all 0.2s ease;
}
.modal-close:hover {
    background: rgba(255, 255, 255, 0.15);
    color: white;
}
.modal-body {
    padding: 24px 28px;
    overflow-y: auto;
    max-height: calc(85vh - 160px);
}
.modal-body::-webkit-scrollbar {
    width: 6px;
}
.modal-body::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 3px;
}
.modal-body::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 3px;
}
.modal-body::-webkit-scrollbar-thumb:hover {
    background: #a1a1a1;
}
.modal-footer {
    padding: 16px 28px 24px;
    background: #fafafa;
    border-top: 1px solid #eee;
    display: flex;
    justify-content: flex-end;
    gap: 12px;
}
.modal-footer .btn {
    min-width: 100px;
    justify-content: center;
}

/* Alerts */
.alert {
    padding: 12px 16px;
    border-radius: 10px;
    margin-bottom: 16px;
}
.alert-success { background: #e8f5e9; color: #2e7d32; }
.alert-danger { background: #ffebee; color: #c62828; }

/* Progress Bar */
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

/* Utility */
.actions { display: flex; gap: 8px; justify-content: center; align-items: center; }
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
.appliance-name {
    display: inline;
    font-size: 16px;
    font-weight: 400;
    cursor: pointer;
}
.appliance-name:hover {
    font-weight: 500;
}
.appliance-explain {
    margin-left: 57px;
    margin-top: -15px;
    border-top: 1px solid #CCCC;
    font-style: italic;
    font-size: 12px;
    color: #595858;
}
.appliance-description {
    margin-left: 57px;
    margin-top: 2px;
    font-size: 11px;
    color: #888;
    font-style: italic;
}
.vm-title {
    display: inline;
    margin-left: 10px;
    font-size: 14px;
    font-weight: 400;
    color: #5a5a5a;
}
.description-vm-title {
    font-size: 13px;
    color: #888;
    font-style: italic;
    margin-top: 5px;
    margin-left: 0;
}
.edit-description-link {
    font-size: 12px;
    color: var(--primary);
    font-style: normal;
    margin-left: 8px;
}
.edit-description-link:hover {
    text-decoration: underline;
}
tbody a:hover {
    font-weight: normal;
    color: #005447;
    text-decoration: underline;
}
.vm-descriptions-row {
    font-size: 11px;
    color: #888;
    font-style: italic;
    margin-left: 24px;
    margin-top: 2px;
}
#vmList tr td {
    vertical-align: middle;
}
#vmList td:last-child,
table th:last-child {
    text-align: right !important;
    width: 70px !important;
    min-width: 70px !important;
}
#vmList td:last-child .action-menu {
    display: inline-block;
}
`

// DockerPageCSS contains styles specific to the Docker/Registry page
const DockerPageCSS = `
.search-box {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
}
.search-box input {
    flex: 1;
    padding: 12px 16px;
    border: 2px solid #e8e8e8;
    border-radius: 10px;
    font-size: 14px;
    background: #fafafa;
    transition: all 0.2s ease;
}
.search-box input:hover {
    border-color: #d0d0d0;
    background: #f5f5f5;
}
.search-box input:focus {
    outline: none;
    border-color: var(--primary);
    background: white;
    box-shadow: 0 0 0 4px rgba(25, 118, 210, 0.1);
}
.image-result {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px;
    border-bottom: 1px solid var(--border-color);
    transition: background 0.15s;
}
.image-result:hover {
    background: #fafafa;
}
.image-result:last-child {
    border-bottom: none;
}
.image-info {
    flex: 1;
}
.image-info h4 {
    font-size: 15px;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 4px;
}
.image-info p {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 4px;
}
.image-info .image-meta {
    display: flex;
    gap: 15px;
    font-size: 12px;
    color: var(--text-secondary);
}
.image-info .image-meta span {
    display: flex;
    align-items: center;
    gap: 4px;
}
.image-info .image-meta .material-icons {
    font-size: 14px;
}

/* Tabs */
.tabs {
    display: flex;
    border-bottom: 2px solid var(--border-color);
    margin-bottom: 20px;
}
.tab {
    padding: 12px 20px;
    border: none;
    background: none;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-secondary);
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: all 0.2s;
}
.tab:hover {
    color: var(--primary);
}
.tab.active {
    color: var(--primary);
    border-bottom-color: var(--primary);
}
.tab-content {
    display: none;
}
.tab-content.active {
    display: block;
}

/* Jobs */
.job-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px;
    border-bottom: 1px solid var(--border-color);
}
.job-item:last-child {
    border-bottom: none;
}
.job-info {
    flex: 1;
}
.job-info h4 {
    font-size: 14px;
    font-weight: 500;
    margin-bottom: 4px;
}
.job-progress {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 8px;
}
.job-progress .progress-bar {
    flex: 1;
    max-width: 200px;
}

/* Compose Upload */
.compose-upload-area {
    border: 2px dashed var(--border-color);
    border-radius: 12px;
    padding: 40px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
}
.compose-upload-area:hover {
    border-color: var(--primary);
    background: rgba(25, 118, 210, 0.05);
}
.compose-upload-area .material-icons {
    font-size: 48px;
    color: var(--text-secondary);
    margin-bottom: 10px;
}
.compose-upload-area p {
    color: var(--text-secondary);
    margin-bottom: 5px;
}
.compose-upload-area small {
    color: var(--text-secondary);
    font-size: 12px;
}

/* Services */
.service-list {
    margin-top: 15px;
}
.service-item {
    display: flex;
    align-items: center;
    padding: 12px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    margin-bottom: 8px;
    transition: all 0.15s;
}
.service-item:hover {
    border-color: var(--primary);
    background: rgba(25, 118, 210, 0.02);
}
.service-item input[type="checkbox"] {
    margin-right: 10px;
}
.service-item .service-name {
    flex: 1;
    font-weight: 500;
}
.service-item .service-image {
    color: var(--text-secondary);
    font-size: 13px;
}
.service-item .service-env {
    font-size: 11px;
    color: var(--text-secondary);
    margin-left: 10px;
}
.service-item .service-env .env-badge {
    display: inline-block;
    padding: 2px 6px;
    background: rgba(25, 118, 210, 0.1);
    border-radius: 4px;
    margin-right: 4px;
    font-family: monospace;
}

/* Environment Variables Container */
.env-vars-container {
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 10px;
    background: #fafafa;
}
.env-var-row {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
    align-items: center;
}
.env-var-row:last-child {
    margin-bottom: 0;
}
.env-var-row input[type="text"] {
    flex: 1;
    padding: 8px 10px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 13px;
    font-family: monospace;
}
.env-var-row input[type="text"]:first-child {
    max-width: 150px;
}
.env-var-row .btn-icon {
    padding: 6px;
    min-width: auto;
    background: none;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-secondary);
}
.env-var-row .btn-icon:hover {
    background: #f0f0f0;
    color: var(--danger);
}
.env-var-row .btn-icon .material-icons {
    font-size: 18px;
}
`

// ConsolePageCSS contains styles for the VM console page
const ConsolePageCSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'lato','Trebuchet MS', 'Helvetica', sans-serif;
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
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    transition: all 0.15s;
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
`
