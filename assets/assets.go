package assets

import (
	_ "embed"
)

//go:embed xterm.css
var XtermCSS []byte

//go:embed xterm.min.js
var XtermJS []byte

//go:embed xterm-addon-fit.min.js
var XtermAddonFitJS []byte

//go:embed material-icons.ttf
var MaterialIconsTTF []byte

// MaterialIconsCSS returns the CSS for Material Icons with embedded font
// The font is served at /assets/material-icons.ttf
var MaterialIconsCSS = `@font-face {
  font-family: 'Material Icons';
  font-style: normal;
  font-weight: 400;
  src: url(/assets/material-icons.ttf) format('truetype');
}

.material-icons {
  font-family: 'Material Icons';
  font-weight: normal;
  font-style: normal;
  font-size: 24px;
  line-height: 1;
  letter-spacing: normal;
  text-transform: none;
  display: inline-block;
  white-space: nowrap;
  word-wrap: normal;
  direction: ltr;
  -webkit-font-feature-settings: 'liga';
  -webkit-font-smoothing: antialiased;
}`
