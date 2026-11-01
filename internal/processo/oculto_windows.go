//go:build windows

// Package processo roda ferramentas sem mostrar nada na tela de quem usa o programa.
package processo

import (
	"os/exec"
	"syscall"
)

// criarSemJanela e o CREATE_NO_WINDOW: sem isso, cada ferramenta de linha de comando
// pisca uma janela preta quando o programa principal nao tem console.
const criarSemJanela = 0x08000000

// Ocultar impede que o processo abra uma janela.
func Ocultar(c *exec.Cmd) *exec.Cmd {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: criarSemJanela}
	return c
}

// UsarConsoleDoPai liga a saida ao terminal de quem chamou, se houver. O executavel nao
// abre janela propria, mas os comandos de linha continuam imprimindo no terminal.
func UsarConsoleDoPai() {
	const pai = ^uintptr(0)
	syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole").Call(pai)
}
