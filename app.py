from flask import Flask, request, render_template_string

app = Flask(__name__)

html_form = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Abertura de Chamado</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f9; }
        .wrap { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; margin-bottom: 20px; }
        label { display: block; margin-top: 15px; font-weight: bold; }
        input, select, textarea, button { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ccc; border-radius: 5px; }
        button { background: #007BFF; color: white; border: none; cursor: pointer; margin-top: 20px; }
        button:hover { background: #0056b3; }
        .error { border: 2px solid red; background-color: #ffe6e6; }
    </style>
    <script>
        function capitalizeWords(input) {
            input.value = input.value.replace(/\\b\\w/g, char => char.toUpperCase());
        }

        function validateForm() {
            let requiredFields = ["cliente", "suporte", "representante", "sistema", "modulo", "ocorrencia", "tipo", "descricao"];
            let valid = true;

            requiredFields.forEach(function(id) {
                let field = document.getElementById(id);
                if (!field.value.trim()) {
                    field.classList.add("error");
                    valid = false;
                } else {
                    field.classList.remove("error");
                }
            });

            return valid;
        }
    </script>
</head>
<body>
    <div class="wrap">
        <h2>Abertura de Chamado</h2>
        <form method="post" onsubmit="return validateForm()">
            <label for="cliente">Nome do Cliente:</label>
            <input type="text" id="cliente" name="cliente" oninput="capitalizeWords(this)">

            <label for="suporte">Nome do Suporte:</label>
            <input type="text" id="suporte" name="suporte" oninput="capitalizeWords(this)">

            <label for="representante">Representante:</label>
            <select id="representante" name="representante">
                <option value="">Selecione...</option>
                <option>João</option>
                <option>Maria</option>
                <option>Carlos</option>
            </select>

            <label for="sistema">Sistema:</label>
            <select id="sistema" name="sistema">
                <option value="">Selecione...</option>
                <option>WebLíder</option>
                <option>WebNotas</option>
                <option>PDV</option>
            </select>

            <label for="modulo">Módulo:</label>
            <select id="modulo" name="modulo">
                <option value="">Selecione...</option>
                <option>Cadastro</option>
                <option>Relatórios</option>
                <option>Financeiro</option>
            </select>

            <label for="ocorrencia">Ocorrência:</label>
            <select id="ocorrencia" name="ocorrencia">
                <option value="">Selecione...</option>
                <option>Erro</option>
                <option>Dúvida</option>
                <option>Solicitação</option>
            </select>

            <label for="tipo">Tipo:</label>
            <select id="tipo" name="tipo">
                <option value="">Selecione...</option>
                <option>Dúvida</option>
                <option>Melhoria</option>
                <option>Bug</option>
            </select>

            <label for="descricao">Descrição / Solicitação:</label>
            <textarea id="descricao" name="descricao" rows="4"></textarea>

            <button type="submit">Salvar Chamado</button>
        </form>
    </div>
</body>
</html>
"""

success_page = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Chamado Salvo</title>
    <style>
        body { font-family: Arial, sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; background:#f4f4f9; }
        .box { background:#fff; padding:40px; border-radius:8px; text-align:center; box-shadow:0 2px 10px rgba(0,0,0,0.1); }
        button { margin:10px; padding:10px 20px; border:none; border-radius:5px; cursor:pointer; }
        .btn-exit { background:#dc3545; color:#fff; }
        .btn-new { background:#28a745; color:#fff; }
    </style>
    <script>
        function sair() {
            window.close();
        }
        function novoChamado() {
            window.location.href = "/";
        }
    </script>
</head>
<body>
    <div class="box">
        <h2>Chamado Salvo com Sucesso!</h2>
        <button class="btn-exit" onclick="sair()">Sair</button>
        <button class="btn-new" onclick="novoChamado()">Abrir Novo Chamado</button>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cliente = request.form.get("cliente")
        suporte = request.form.get("suporte")
        representante = request.form.get("representante")
        sistema = request.form.get("sistema")
        modulo = request.form.get("modulo")
        ocorrencia = request.form.get("ocorrencia")
        tipo = request.form.get("tipo")
        descricao = request.form.get("descricao")

        if not all([cliente, suporte, representante, sistema, modulo, ocorrencia, tipo, descricao]):
            return render_template_string(html_form)

        return render_template_string(success_page)
    return render_template_string(html_form)

if __name__ == "__main__":
    app.run(debug=True)
