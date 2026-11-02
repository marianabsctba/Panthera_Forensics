package caso

import (
	"encoding/json"
	"strings"
	"testing"
)

// evento grava um registro no formato em que os logs do Windows chegam ao banco.
func evento(t *testing.T, c *Caso, quando, fonte, id, numero string, campos map[string]string) {
	t.Helper()
	lista := []map[string]string{}
	for k, v := range campos {
		lista = append(lista, map[string]string{"@Name": k, "#text": v})
	}
	payload, _ := json.Marshal(map[string]any{"EventData": map[string]any{"Data": lista}})
	dados, _ := json.Marshal(map[string]string{"Computer": "SRV.exemplo", "EventId": id, "EventRecordId": numero, "Provider": "x", "Payload": string(payload)})
	if _, err := c.DB.Exec(`INSERT INTO registros(execucao_id,tipo,quando,fonte,descricao,dados) VALUES(1,'evento',?,?,?,?)`, quando, fonte, "Evento "+id, string(dados)); err != nil {
		t.Fatal(err)
	}
}

func origem(t *testing.T, a Acessos, nome string) OrigemAcesso {
	t.Helper()
	for _, o := range a.Origens {
		if o.Origem == nome {
			return o
		}
	}
	t.Fatalf("origem %s ausente: %+v", nome, a.Origens)
	return OrigemAcesso{}
}

func TestAcessosSomaFalhasEntradaEAcoes(t *testing.T) {
	c := semear(t)
	falha := map[string]string{"IpAddress": "36.133.110.87", "WorkstationName": "kali", "TargetUserName": "Administrator"}
	evento(t, c, "2024-02-05T10:00:00Z", "Security", "4625", "1", falha)
	evento(t, c, "2024-02-05T10:00:01Z", "Security", "4625", "2", falha)
	// A mesma linha de novo, como em uma copia de sombra do log.
	evento(t, c, "2024-02-05T10:00:01Z", "Security", "4625", "2", falha)
	evento(t, c, "2024-02-05T10:01:00Z", "Security", "4624", "3", map[string]string{
		"IpAddress": "::ffff:36.133.110.87", "WorkstationName": "kali", "TargetUserName": "administrator",
		"LogonType": "10", "TargetLogonId": "0xABC", "TargetLinkedLogonId": "0xDEF"})
	evento(t, c, "2024-02-05T10:02:00Z", "Security", "4625", "4", falha)
	evento(t, c, "2024-02-05T11:00:00Z", "Security", "4720", "5", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0xdef", "TargetUserName": "admin", "TargetSid": "S-1-5-21-9"})
	evento(t, c, "2024-02-05T11:01:00Z", "Security", "4732", "6", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0xABC", "MemberName": "-", "MemberSid": "S-1-5-21-9", "TargetUserName": "Administrators"})
	evento(t, c, "2024-02-05T11:02:00Z", "Security", "4728", "7", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0x999", "MemberName": "CN=ana,CN=Users,DC=x", "TargetUserName": "Domain Admins"})

	a, err := c.Acessos()
	if err != nil {
		t.Fatal(err)
	}
	o := origem(t, a, "36.133.110.87")
	if o.Rede != "publica" || o.Falhas != 3 || o.Entradas != 1 || o.FalhasAntes != 2 {
		t.Fatalf("soma errada: %+v", o)
	}
	if o.ContasTotal != 1 || o.Contas[0].Falhas != 3 || o.Contas[0].Entradas != 1 {
		t.Fatalf("contas com maiusculas diferentes deviam ser uma so: %+v", o.Contas)
	}
	if a.Repetidos != 1 {
		t.Fatalf("repetidos = %d", a.Repetidos)
	}
	if o.Tipos["área de trabalho remota"] != 1 || len(o.Estacoes) != 1 || o.Estacoes[0] != "KALI" {
		t.Fatalf("tipo ou estacao: %+v", o)
	}
	if len(o.Acoes) != 2 {
		t.Fatalf("acoes da sessao, inclusive pela sessao ligada: %+v", o.Acoes)
	}
	textos := []string{}
	for _, m := range a.Marcos {
		textos = append(textos, m.Descricao)
	}
	juntos := strings.Join(textos, "\n")
	for _, esperado := range []string{
		"Primeira entrada de 36.133.110.87, na conta administrator",
		"Conta admin criada por Administrator, em sessão vinda de 36.133.110.87",
		"admin posta no grupo Administrators",
		"ana posta no grupo Domain Admins por Administrator",
	} {
		if !strings.Contains(juntos, esperado) {
			t.Errorf("falta %q em:\n%s", esperado, juntos)
		}
	}
	// Sem sessao conhecida, nao se atribui a mudanca a origem nenhuma.
	if strings.Contains(juntos, "Domain Admins por Administrator, em sessão") {
		t.Errorf("atribuiu sessao desconhecida:\n%s", juntos)
	}
}

func TestAcessosCitaEntradaVizinhaSemAfirmarAutoria(t *testing.T) {
	c := semear(t)
	evento(t, c, "2024-02-05T23:00:28Z", "Security", "4624", "1", map[string]string{
		"IpAddress": "185.229.66.183", "TargetUserName": "Administrator", "LogonType": "10", "TargetLogonId": "0x1"})
	evento(t, c, "2024-02-05T23:02:00Z", "Security", "4720", "2", map[string]string{
		"SubjectUserName": "administrator", "SubjectLogonId": "0x81BFAB", "TargetUserName": "admin", "TargetSid": "S-1"})
	evento(t, c, "2024-02-05T23:02:22Z", "Security", "4732", "3", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0x81BFAB", "MemberName": "cn=A Admin,DC=x", "MemberSid": "S-1", "TargetUserName": "Administrators"})
	evento(t, c, "2024-02-05T23:03:00Z", "Security", "4728", "4", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0x81BFAB", "MemberName": "cn=B Silva,DC=x", "MemberSid": "S-2", "TargetUserName": "Domain Admins"})
	// Passou da janela: a entrada antiga nao e mais citada.
	evento(t, c, "2024-02-06T00:30:00Z", "Security", "4726", "5", map[string]string{
		"SubjectUserName": "Administrator", "SubjectLogonId": "0x81BFAB", "TargetUserName": "admin"})
	a, err := c.Acessos()
	if err != nil {
		t.Fatal(err)
	}
	o := origem(t, a, "185.229.66.183")
	if len(o.Acoes) != 0 || len(o.Proximas) != 3 {
		t.Fatalf("vizinhanca nao pode virar autoria: %+v", o)
	}
	juntos := []string{}
	for _, m := range a.Marcos {
		juntos = append(juntos, m.Descricao)
	}
	texto := strings.Join(juntos, "\n")
	for _, esperado := range []string{
		"Conta admin criada por administrator. Última entrada remota nessa conta: 185.229.66.183, 1 min antes, o que não prova a autoria",
		"admin posta no grupo Administrators",
		"B Silva posta no grupo Domain Admins",
		"Conta admin apagada por Administrator\n",
	} {
		if !strings.Contains(texto+"\n", esperado) {
			t.Errorf("falta %q em:\n%s", esperado, texto)
		}
	}
}

func TestAcessosResolveMembroRegistradoAntesDaConta(t *testing.T) {
	c := semear(t)
	evento(t, c, "2015-03-22T15:51:54Z", "Security", "4728", "1", map[string]string{
		"SubjectUserName": "informant", "MemberName": "-", "MemberSid": "S-1-9", "TargetUserName": "None"})
	evento(t, c, "2015-03-22T15:51:54Z", "Security", "4720", "2", map[string]string{
		"SubjectUserName": "informant", "TargetUserName": "admin11", "TargetSid": "S-1-9"})
	a, err := c.Acessos()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.Marcos[0].Descricao, "admin11 posta no grupo None") {
		t.Fatalf("membro sem nome: %+v", a.Marcos)
	}
}

func TestAcessosIgnoraLocalEOutrosCanais(t *testing.T) {
	c := semear(t)
	evento(t, c, "2024-01-01T00:00:00Z", "Security", "4624", "1", map[string]string{"IpAddress": "127.0.0.1", "TargetUserName": "ana"})
	evento(t, c, "2024-01-01T00:00:01Z", "Security", "4624", "2", map[string]string{"IpAddress": "-", "WorkstationName": "SRV", "TargetUserName": "ana"})
	evento(t, c, "2024-01-01T00:00:02Z", "Application", "4625", "3", map[string]string{"IpAddress": "8.8.8.8"})
	a, err := c.Acessos()
	if err != nil {
		t.Fatal(err)
	}
	if a.TotalOrigens != 0 {
		t.Fatalf("acesso local ou de outro canal contou: %+v", a.Origens)
	}
}

func TestAcessosSeparaAnonimaEOrdenaPorFatos(t *testing.T) {
	c := semear(t)
	evento(t, c, "2024-01-01T00:00:00Z", "Security", "4624", "1", map[string]string{"IpAddress": "8.8.8.8", "TargetUserName": "ANONYMOUS LOGON", "LogonType": "3"})
	evento(t, c, "2024-01-01T00:00:01Z", "Security", "4624", "2", map[string]string{"IpAddress": "10.0.0.5", "TargetUserName": "ana", "LogonType": "3"})
	evento(t, c, "2024-01-01T00:00:02Z", "Security", "4625", "3", map[string]string{"IpAddress": "-", "WorkstationName": "kali", "TargetUserName": "ana"})
	evento(t, c, "2024-01-01T00:00:03Z", "Security", "4624", "4", map[string]string{"IpAddress": "1.1.1.1", "TargetUserName": "ana", "LogonType": "3"})
	a, err := c.Acessos()
	if err != nil {
		t.Fatal(err)
	}
	if o := origem(t, a, "8.8.8.8"); o.Entradas != 0 || o.Anonimas != 1 || o.PrimeiraEntrada != "" {
		t.Fatalf("sessao anonima contou como entrada: %+v", o)
	}
	ordem := []string{}
	for _, o := range a.Origens {
		ordem = append(ordem, o.Origem)
	}
	if got := strings.Join(ordem, " "); got != "1.1.1.1 KALI 8.8.8.8 10.0.0.5" {
		t.Fatalf("ordem = %s", got)
	}
	if origem(t, a, "KALI").Rede != "nome" || origem(t, a, "10.0.0.5").Rede != "interna" {
		t.Fatalf("rede errada: %+v", a.Origens)
	}
}
