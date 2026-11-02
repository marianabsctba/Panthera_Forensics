package disco

import (
	"strings"
	"testing"
)

const tarefaExemplo = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2024-02-06T21:49:21</Date><Author>DOMINIO\ana</Author><URI>\Copia</URI></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2024-02-09T21:46:24</StartBoundary></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>ana</UserId></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Users\ana\Downloads\a.exe</Command><Arguments>-x 1</Arguments></Exec></Actions>
</Task>`

func TestInterpretarTarefa(t *testing.T) {
	tarefa, ok := InterpretarTarefa(tarefaExemplo)
	if !ok {
		t.Fatal("tarefa nao interpretada")
	}
	if tarefa.Nome != `\Copia` || tarefa.Autor != `DOMINIO\ana` || tarefa.Conta != "ana" {
		t.Fatalf("campos errados: %+v", tarefa)
	}
	if len(tarefa.Comandos) != 1 || tarefa.Comandos[0] != `C:\Users\ana\Downloads\a.exe -x 1` {
		t.Fatalf("comando errado: %v", tarefa.Comandos)
	}
	if len(tarefa.Gatilhos) != 1 || tarefa.Gatilhos[0] != "TimeTrigger 2024-02-09T21:46:24" {
		t.Fatalf("gatilho errado: %v", tarefa.Gatilhos)
	}
}

func TestInterpretarTarefaRecusaOutroXML(t *testing.T) {
	if _, ok := InterpretarTarefa("<outra/>"); ok {
		t.Fatal("XML sem tarefa foi aceito")
	}
	if _, ok := InterpretarTarefa("nao e xml"); ok {
		t.Fatal("texto foi aceito")
	}
}

func TestTarefaComProgramaEmPastaDeUsuarioViraAlerta(t *testing.T) {
	e := Entrada{Caminho: "/Windows/System32/Tasks/Copia", Inode: "1-128-1", Criacao: 1707256161}
	tarefa, _ := InterpretarTarefa(tarefaExemplo)
	r := registroDaTarefa(tarefa, e, 2048)
	if r.Tipo != "alerta" || r.Severidade != "media" {
		t.Fatalf("esperava alerta: %+v", r)
	}
	if !strings.Contains(r.Descricao, "-x 1") || r.Quando != "2024-02-06T21:49:21Z" {
		t.Fatalf("registro errado: %+v", r)
	}
	tarefa.Comandos = []string{`%windir%\system32\defrag.exe -c`}
	if r := registroDaTarefa(tarefa, e, 2048); r.Tipo != "evento" {
		t.Fatalf("tarefa do sistema virou alerta: %+v", r)
	}
}
