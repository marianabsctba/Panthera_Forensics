//go:build !windows

// Package processo roda ferramentas sem mostrar nada na tela de quem usa o programa.
package processo

import "os/exec"

// Ocultar nao precisa fazer nada: fora do Windows, processo de linha de comando nao abre
// janela propria.
func Ocultar(c *exec.Cmd) *exec.Cmd { return c }

// UsarConsoleDoPai nao precisa fazer nada fora do Windows.
func UsarConsoleDoPai() {}
