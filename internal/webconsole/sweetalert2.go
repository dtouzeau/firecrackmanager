package webconsole

import (
	_ "embed"
)

//go:embed assets/sweetalert2.min.js
var SweetAlert2JS string

//go:embed assets/sweetalert2.min.css
var SweetAlert2CSS string
