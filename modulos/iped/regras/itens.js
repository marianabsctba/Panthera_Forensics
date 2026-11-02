// Traz para o caso o que o exame profundo leu por dentro e nao aparece na lista de arquivos:
// e-mails, historico do Internet Explorer e o banco da busca do Windows. Roda no Java da
// propria ferramenta, sem abrir janela. Argumentos: pasta do exame, pasta de saida.
var Paths = Java.type("java.nio.file.Paths");
var Files = Java.type("java.nio.file.Files");
var FSDirectory = Java.type("org.apache.lucene.store.FSDirectory");
var DirectoryReader = Java.type("org.apache.lucene.index.DirectoryReader");
var DriverManager = Java.type("java.sql.DriverManager");
var GZIPInputStream = Java.type("java.util.zip.GZIPInputStream");
var ByteArrayInputStream = Java.type("java.io.ByteArrayInputStream");
var ByteArrayOutputStream = Java.type("java.io.ByteArrayOutputStream");
var ByteArray = Java.type("byte[]");
var JString = Java.type("java.lang.String");
var HashSet = Java.type("java.util.HashSet");
var PrintStream = Java.type("java.io.PrintStream");
var FileOutputStream = Java.type("java.io.FileOutputStream");

var exame = String($ARG[0]), destino = String($ARG[1]);
var leitor = DirectoryReader.open(FSDirectory.open(Paths.get(exame, "iped", "index")));

function escritor(nome) {
  return new PrintStream(new FileOutputStream(Paths.get(destino, nome).toFile()), true, "UTF-8");
}
var mensagens = escritor("mensagens.jsonl");
var historico = escritor("historico.jsonl");
var buscaWindows = escritor("busca-windows.jsonl");

// O conteudo dos itens internos fica em bancos do exame, comprimido, pelo hash do item.
function conteudo(doc) {
  var banco = doc.get("dataSourcePath"), id = doc.get("idInDataSource");
  if (banco === null || id === null || String(banco).indexOf("storage") < 0) return null;
  var arquivo = Paths.get(exame, String(banco));
  if (!Files.exists(arquivo)) return null;
  var conexao = DriverManager.getConnection("jdbc:sqlite:" + arquivo.toString());
  try {
    var consulta = conexao.prepareStatement("SELECT data FROM t1 WHERE id=?");
    consulta.setString(1, id);
    var linhas = consulta.executeQuery();
    if (!linhas.next()) return null;
    var entrada = new GZIPInputStream(new ByteArrayInputStream(linhas.getBytes(1)));
    var saida = new ByteArrayOutputStream();
    var pedaco = new ByteArray(65536);
    for (var n = entrada.read(pedaco); n > 0; n = entrada.read(pedaco)) saida.write(pedaco, 0, n);
    return new JString(saida.toByteArray(), "UTF-8");
  } finally {
    conexao.close();
  }
}

function semEntidades(texto) {
  return String(texto).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&nbsp;/g, " ").replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(parseInt(n, 10)); })
    .replace(/&amp;/g, "&");
}

function textoDoHtml(html) {
  return semEntidades(String(html).replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " "))
    .replace(/\s+/g, " ").trim();
}

function semEndereco(texto) {
  return texto === null ? "" : String(texto).replace(/<[^>]*>/g, "").trim();
}

// Anexos sao itens filhos da mensagem: uma primeira volta acha as mensagens.
var campos = new HashSet();
["id", "parentId", "name", "category", "contentType"].forEach(function (c) { campos.add(c); });
var ehMensagem = {}, anexos = {};
for (var i = 0; i < leitor.maxDoc(); i++) {
  var d = leitor.document(i, campos);
  if (String(d.get("contentType")) === "message/outlook-pst" || String(d.get("category")) === "Emails") ehMensagem[d.get("id")] = true;
}
for (var i = 0; i < leitor.maxDoc(); i++) {
  var d = leitor.document(i, campos);
  var pai = d.get("parentId");
  if (pai !== null && ehMensagem[pai]) (anexos[pai] = anexos[pai] || []).push(String(d.get("name")));
}

function mensagem(d) {
  var assunto = d.get("Message-Subject");
  if (assunto === null) return;
  var corpo = d.get("Message-Body");
  // O indice guarda so o comeco de um corpo longo. O conteudo traz o corpo inteiro, depois
  // dos cabecalhos: o comeco que o indice guardou mostra onde ele comeca.
  if (corpo !== null && String(corpo).indexOf("(...)") >= 0) {
    var comeco = String(corpo).split("(...)")[0].replace(/\s+/g, " ").trim().substring(0, 12);
    var html = conteudo(d);
    if (html !== null) {
      var texto = textoDoHtml(html), onde = texto.indexOf(comeco);
      if (onde >= 0) corpo = texto.substring(onde);
    }
  }
  mensagens.println(JSON.stringify({
    caminho: String(d.get("path")),
    assunto: String(assunto),
    de: semEndereco(d.get("Communication:From")),
    para: semEndereco(d.get("Communication:To")),
    remetente: String(d.get("Message:Raw-Header:Return-Path") || ""),
    enderecos: Java.from(d.getValues("Regex:EMAIL")).join(", "),
    data: String(d.get("Communication:Date") || ""),
    corpo: corpo === null ? "" : String(corpo).replace(/\s+/g, " ").trim(),
    anexos: anexos[d.get("id")] ? "Anexos: " + anexos[d.get("id")].join(", ") : "",
    pasta: String(d.get("path")).split(">>").pop().replace("[root]/Root - Mailbox/IPM_SUBTREE/", "").replace(/\/[^\/]*$/, ""),
    situacao: String(d.get("deleted")) === "true" ? "apagada e recuperada" : "ativa",
  }));
}

function visita(d) {
  historico.println(JSON.stringify({
    caminho: String(d.get("path")),
    url: String(d.get("URL") || ""),
    visita: String(d.get("visitDate") || ""),
  }));
}

// A tabela vem como HTML: a primeira linha traz o nome das colunas. So os campos preenchidos
// seguem adiante, porque o banco tem centenas de colunas quase sempre vazias.
function tabelaDeBusca(d) {
  var html = conteudo(d);
  if (html === null) return;
  var cabecalho = null;
  String(html).split("<tr>").forEach(function (linha) {
    if (linha.indexOf("<td>") < 0) return;
    var celulas = linha.split("</tr>")[0].split("<td>").slice(1).map(function (c) {
      return semEntidades(c.replace(/<\/td>\s*$/, "").replace(/<\/?b>/g, ""));
    });
    if (cabecalho === null) {
      cabecalho = celulas;
      return;
    }
    var registro = { tabela: String(d.get("name")) };
    celulas.forEach(function (valor, n) {
      if (valor === "" || !cabecalho[n]) return;
      valor = valor.replace(/\\\\/g, "\\");
      // So o resumo traz quebras escritas como texto. Em um caminho, \n pode ser uma pasta.
      if (cabecalho[n] === "System_Search_AutoSummary") valor = valor.replace(/\\[nr]/g, " ").replace(/\s+/g, " ");
      registro[cabecalho[n]] = valor;
    });
    buscaWindows.println(JSON.stringify(registro));
  });
}

for (var i = 0; i < leitor.maxDoc(); i++) {
  var d = leitor.document(i);
  var tipo = String(d.get("contentType")), nome = String(d.get("name"));
  if (tipo === "message/outlook-pst" || String(d.get("category")) === "Emails") {
    mensagem(d);
  } else if (tipo === "application/x-edge-history-registry") {
    visita(d);
  } else if (tipo === "application/x-edb-table" && nome.indexOf("SystemIndex_0A") >= 0) {
    tabelaDeBusca(d);
  }
}
mensagens.close();
historico.close();
buscaWindows.close();
leitor.close();
