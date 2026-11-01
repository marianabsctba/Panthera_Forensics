// Package custodia mantem o registro encadeado de tudo o que acontece em um caso.
// Cada linha guarda o hash da anterior, entao qualquer alteracao, remocao ou
// reordenacao de uma linha ja gravada quebra a verificacao.
package custodia

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Genese e o hash anterior da primeira entrada de um registro.
const Genese = "0000000000000000000000000000000000000000000000000000000000000000"

// Entrada e uma linha do registro de custodia.
type Entrada struct {
	Seq      int64          `json:"seq"`
	Quando   string         `json:"quando"`
	Autor    string         `json:"autor"`
	Acao     string         `json:"acao"`
	Detalhes map[string]any `json:"detalhes,omitempty"`
	Anterior string         `json:"anterior"`
	Hash     string         `json:"hash"`
}

// Registro e um arquivo de custodia aberto para acrescimo.
type Registro struct {
	mu       sync.Mutex
	caminho  string
	autor    string
	seq      int64
	anterior string
	agora    func() time.Time
}

// Abrir carrega o registro, confere a cadeia existente e o deixa pronto para acrescimo.
func Abrir(caminho, autor string) (*Registro, error) {
	r := &Registro{caminho: caminho, autor: autor, anterior: Genese, agora: time.Now}
	entradas, err := Ler(caminho)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if problema := Verificar(entradas); problema != nil {
			return nil, problema
		}
		if n := len(entradas); n > 0 {
			r.seq = entradas[n-1].Seq
			r.anterior = entradas[n-1].Hash
		}
	}
	return r, nil
}

// Registrar acrescenta uma entrada e forca a gravacao em disco.
func (r *Registro) Registrar(acao string, detalhes map[string]any) (Entrada, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := Entrada{
		Seq:      r.seq + 1,
		Quando:   r.agora().UTC().Format(time.RFC3339Nano),
		Autor:    r.autor,
		Acao:     acao,
		Detalhes: detalhes,
		Anterior: r.anterior,
	}
	h, err := calcular(e)
	if err != nil {
		return e, err
	}
	e.Hash = h
	linha, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	f, err := os.OpenFile(r.caminho, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return e, err
	}
	defer f.Close()
	if _, err := f.Write(append(linha, '\n')); err != nil {
		return e, err
	}
	if err := f.Sync(); err != nil {
		return e, err
	}
	r.seq, r.anterior = e.Seq, e.Hash
	return e, nil
}

// Ler devolve todas as entradas do arquivo, sem conferir a cadeia.
func Ler(caminho string) ([]Entrada, error) {
	f, err := os.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entradas []Entrada
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		var e Entrada
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("linha %d ilegivel: %w", n, err)
		}
		entradas = append(entradas, e)
	}
	return entradas, sc.Err()
}

// Verificar confere sequencia, encadeamento e hash de cada entrada.
// Sozinha ela nao detecta a remocao das ultimas linhas: para isso, compare o
// hash final com um valor guardado fora do caso, como o impresso no relatorio.
func Verificar(entradas []Entrada) error {
	anterior := Genese
	for i, e := range entradas {
		if e.Seq != int64(i+1) {
			return fmt.Errorf("entrada %d: sequencia %d fora de ordem", i+1, e.Seq)
		}
		if e.Anterior != anterior {
			return fmt.Errorf("entrada %d: encadeamento quebrado", e.Seq)
		}
		h, err := calcular(e)
		if err != nil {
			return err
		}
		if h != e.Hash {
			return fmt.Errorf("entrada %d: conteudo alterado", e.Seq)
		}
		anterior = e.Hash
	}
	return nil
}

func calcular(e Entrada) (string, error) {
	e.Hash = ""
	dados, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	soma := sha256.Sum256(dados)
	return hex.EncodeToString(soma[:]), nil
}
