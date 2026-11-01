// Consulta o indice do exame profundo sem abrir nenhuma janela. Roda no Java da propria
// ferramenta, com o jjs. Argumentos: pasta do indice, limite, termos da busca.
// Escreve uma linha JSON por resultado. Os termos entram como frase literal, entao sinais
// como * e : em um hash ou IP nao viram operadores da busca.
var Paths = Java.type("java.nio.file.Paths");
var FSDirectory = Java.type("org.apache.lucene.store.FSDirectory");
var DirectoryReader = Java.type("org.apache.lucene.index.DirectoryReader");
var IndexSearcher = Java.type("org.apache.lucene.search.IndexSearcher");
var PhraseQuery = Java.type("org.apache.lucene.search.PhraseQuery");
var TermQuery = Java.type("org.apache.lucene.search.TermQuery");
var Term = Java.type("org.apache.lucene.index.Term");
var Normalizer = Java.type("java.text.Normalizer");
var JString = Java.type("java.lang.String");
var System = Java.type("java.lang.System");
var PrintStream = Java.type("java.io.PrintStream");

var CAMPO = "content";
var saida = new PrintStream(System.out, true, "UTF-8");

// O indice guarda minusculas sem acento, e separa palavras em qualquer outro sinal.
function termos(texto) {
  var limpo = Normalizer.normalize(new JString(texto).toLowerCase(), Normalizer.Form.NFD)
    .replaceAll("\\p{M}", "");
  return String(limpo).split(/[^a-z0-9]+/).filter(function (t) { return t.length > 0; });
}

var dir = FSDirectory.open(Paths.get($ARG[0]));
var leitor = DirectoryReader.open(dir);
var busca = new IndexSearcher(leitor);
var limite = parseInt($ARG[1], 10);
var lista = termos($ARG.slice(2).join(" "));

var consulta;
if (lista.length === 1) {
  consulta = new TermQuery(new Term(CAMPO, lista[0]));
} else {
  var frase = new PhraseQuery.Builder();
  lista.forEach(function (t) { frase.add(new Term(CAMPO, t)); });
  consulta = frase.build();
}

// O texto de um arquivo fica em fragmentos gravados logo antes do item a que pertencem, e
// so o item guarda o caminho: por isso cada resultado anda para a frente ate encontra-lo.
function itemPrincipal(id) {
  for (var n = id; n < leitor.maxDoc(); n++) {
    var doc = busca.doc(n);
    if (doc.get("path") !== null) return doc;
  }
  return busca.doc(id);
}

// Pede mais do que o limite, porque varios fragmentos podem ser do mesmo arquivo.
var achados = busca.search(consulta, limite * 5);
var vistos = {};
var saidaLinhas = [];
Java.from(achados.scoreDocs).forEach(function (d) {
  var doc = itemPrincipal(d.doc);
  var caminho = String(doc.get("path"));
  if (vistos[caminho] || saidaLinhas.length >= limite) return;
  vistos[caminho] = true;
  saidaLinhas.push(JSON.stringify({
    nome: String(doc.get("name")),
    caminho: caminho,
    categoria: String(doc.get("category")),
    tamanho: String(doc.get("size")),
    apagado: String(doc.get("deleted")),
    md5: String(doc.get("md5")),
  }));
});
saida.println(JSON.stringify({ total: saidaLinhas.length }));
saidaLinhas.forEach(function (l) { saida.println(l); });
leitor.close();