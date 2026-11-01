// Package modulos embute os manifestos que acompanham o executavel. Modulos novos
// podem ficar na pasta modulos ao lado dele, sem recompilar nada.
package modulos

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed */modulo.yaml
var Embutidos embed.FS

//go:embed */regras/*
var regras embed.FS

// PrepararWSL e o script que instala as ferramentas do ambiente Linux dedicado.
//
//go:embed wsl/preparar.sh
var PrepararWSL string

// GravarRegras escreve as regras proprias em dir/<modulo>, para as ferramentas lerem.
func GravarRegras(dir string) error {
	caminhos, err := fs.Glob(regras, "*/regras/*")
	if err != nil {
		return err
	}
	for _, caminho := range caminhos {
		dados, err := regras.ReadFile(caminho)
		if err != nil {
			return err
		}
		pasta := filepath.Join(dir, filepath.Dir(filepath.Dir(caminho)))
		if err := os.MkdirAll(pasta, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(pasta, filepath.Base(caminho)), dados, 0o644); err != nil {
			return err
		}
	}
	return nil
}
