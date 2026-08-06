package web

import "embed"

//go:embed app.css app.js index.html
var Files embed.FS
