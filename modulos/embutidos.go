// Package modulos embute os manifestos que acompanham o executavel. Modulos novos
// podem ficar na pasta modulos ao lado dele, sem recompilar nada.
package modulos

import "embed"

//go:embed */modulo.yaml
var Embutidos embed.FS
