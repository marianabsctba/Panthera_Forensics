package motor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/disco"
)

// FontePreservados marca os arquivos que nenhum modulo soube ler.
const FontePreservados = "Arquivos sem leitura própria"

// limiteTextoPreservado e o que entra na busca de cada arquivo sem leitura propria.
const limiteTextoPreservado = 256 * 1024

// listarPreservados garante que nada entregue fique invisivel: um arquivo sem modulo
// aparece na timeline, e seu texto entra na busca quando for legivel.
func (m *Motor) listarPreservados(ctx context.Context, c *caso.Caso) (int, error) {
	evidencias, err := c.Evidencias()
	if err != nil {
		return 0, err
	}
	linhas, err := c.DB.Query(`SELECT origem_local FROM registros WHERE fonte=?`, FontePreservados)
	if err != nil {
		return 0, err
	}
	vistas := map[string]bool{}
	for linhas.Next() {
		var s string
		if err := linhas.Scan(&s); err != nil {
			linhas.Close()
			return 0, err
		}
		vistas[s] = true
	}
	linhas.Close()
	if err := linhas.Err(); err != nil {
		return 0, err
	}
	var pendentes []caso.Evidencia
	for _, e := range evidencias {
		if e.Tipo == "" && !vistas[localPreservado(e)] {
			pendentes = append(pendentes, e)
		}
	}
	if len(pendentes) == 0 {
		return 0, nil
	}
	bloqueadas := 0
	agora := time.Now().UTC().Format(time.RFC3339)
	tx, err := c.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,args,estado,inicio,fim,registros) VALUES(?,?,?,?,?,?,?,?,?)`,
		"preservados-"+agora, "preservados", FontePreservados, "1", "[]", "concluida", agora, agora, len(pendentes))
	if err != nil {
		return 0, err
	}
	execucao, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, e := range pendentes {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		dados := map[string]any{"caminho": e.Origem, "tamanho": e.Tamanho, "sha256": e.SHA256, "md5": e.MD5}
		tipo, severidade := "evento", ""
		rotulo := "Arquivo preservado: "
		if !legivel(c.CaminhoEvidencia(e.SHA256)) {
			// O hash registrado na entrada continua valendo. O conteudo e que nao esta mais
			// acessivel neste computador, e o exame nao pode fingir que o leu.
			tipo, severidade, rotulo = "alerta", "alta", "Evidência bloqueada ou removida, possivelmente pelo antivírus: "
			bloqueadas++
		} else if texto, ok := textoInicial(c.CaminhoEvidencia(e.SHA256)); ok {
			dados["texto"] = texto
		}
		bruto, err := json.Marshal(dados)
		if err != nil {
			return 0, err
		}
		descricao := rotulo + strings.TrimPrefix(e.Origem, "enviado pela interface: ")
		r, err := tx.Exec(`INSERT INTO registros(execucao_id,tipo,severidade,fonte,descricao,origem_arquivo,origem_local,dados) VALUES(?,?,?,?,?,?,?,?)`,
			execucao, tipo, severidade, FontePreservados, descricao, fmt.Sprintf("%s (evidência %d)", e.Nome, e.ID), localPreservado(e), string(bruto))
		if err != nil {
			return 0, err
		}
		id, err := r.LastInsertId()
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`INSERT INTO busca(rowid,descricao,fonte,dados) VALUES(?,?,?,?)`, id, descricao, FontePreservados, string(bruto)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	_, err = c.Custodia.Registrar("arquivos.listados", map[string]any{"execucao": execucao, "total": len(pendentes), "bloqueadas": bloqueadas})
	return len(pendentes), err
}

func localPreservado(e caso.Evidencia) string {
	return "evidência " + strconv.FormatInt(e.ID, 10)
}

// textoInicial le o comeco do arquivo. So o comeco, e nao o arquivo inteiro: um .log de
// varios GB nao pode travar a analise nem inchar o banco.
func textoInicial(caminho string) (string, bool) {
	f, err := os.Open(caminho)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limiteTextoPreservado))
	if err != nil {
		return "", false
	}
	return disco.TextoLegivel(b)
}
