package caso

import (
	"errors"
	"fmt"
	"syscall"
)

// erroVirusWindows e o ERROR_VIRUS_INFECTED: o antivirus bloqueou a abertura do
// arquivo. Em investigacao isso e comum, porque saidas de ferramentas citam trechos
// de ataques reais e evidencias podem conter malware.
const erroVirusWindows = syscall.Errno(225)

// ExplicarAntivirus troca o erro cru por uma orientacao de tela. O motivo original
// continua no erro encadeado, para a custodia.
func ExplicarAntivirus(err error) error {
	if err == nil || !errors.Is(err, erroVirusWindows) {
		return err
	}
	return fmt.Errorf("o antivírus bloqueou um arquivo deste caso. Guarde os casos em uma pasta excluída do antivírus e processe de novo: %w", err)
}
