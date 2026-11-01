// Ferramenta falsa usada apenas nos testes: le o arquivo recebido e escreve um CSV.
// Com o conteudo "QUEBRAR", termina com erro para simular uma ferramenta que falha.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	entrada, saida := os.Args[1], os.Args[2]
	dados, err := os.ReadFile(entrada)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if strings.Contains(string(dados), "QUEBRAR") {
		fmt.Fprintln(os.Stderr, "falha simulada")
		os.Exit(3)
	}
	// A evidencia precisa continuar somente leitura para a ferramenta.
	if f, err := os.OpenFile(entrada, os.O_WRONLY, 0); err == nil {
		f.Close()
		fmt.Fprintln(os.Stderr, "evidencia gravavel")
		os.Exit(4)
	}
	csv := "Hora,Regra,Nivel,Host,Pos\n" +
		"2026-03-01 07:00:00.000 -03:00,Conta criada,high,PC-01,10\n" +
		"2026-03-01 11:00:00.000 -03:00,Log limpo,crit,pc-01,20\n"
	if err := os.WriteFile(filepath.Join(saida, "resultado.csv"), []byte(csv), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
}
