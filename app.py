from flask import Flask, render_template, request, jsonify
import requests
import os

app = Flask(__name__)

# ===== CONFIG VIA VARIÁVEIS DE AMBIENTE =====
API_KEY   = os.getenv("TRELLO_KEY", "")
TOKEN     = os.getenv("TRELLO_TOKEN", "")
BOARD_ID  = os.getenv("TRELLO_BOARD", "fGQqUBuw")
LIST_NAME = os.getenv("TRELLO_LIST", "Chamados abertos")
# ============================================

TRELLO_BASE = "https://api.trello.com/1"
TIMEOUT = 15  # s


def trello_get(path: str, params: dict | None = None):
    p = {"key": API_KEY, "token": TOKEN}
    if params: p.update(params)
    r = requests.get(f"{TRELLO_BASE}{path}", params=p, timeout=TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"[TRELLO][GET {path}] {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][GET {path}] Resposta não-JSON: {r.text[:300]}")


def trello_post(path: str, params: dict | None = None):
    p = {"key": API_KEY, "token": TOKEN}
    if params: p.update(params)
    r = requests.post(f"{TRELLO_BASE}{path}", params=p, timeout=TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"[TRELLO][POST {path}] {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][POST {path}] Resposta não-JSON: {r.text[:300]}")


def get_board_refs():
    if not API_KEY or not TOKEN:
        raise RuntimeError("[CONFIG] Defina TRELLO_KEY e TRELLO_TOKEN nas variáveis de ambiente.")

    lists = trello_get(f"/boards/{BOARD_ID}/lists", {})
    list_id = next((l["id"] for l in lists if l.get("name") == LIST_NAME), None)
    if not list_id:
        nomes = ", ".join(l.get("name", "?") for l in lists)
        raise RuntimeError(f'[TRELLO] Lista "{LIST_NAME}" não encontrada. Disponíveis: {nomes}')

    labels = trello_get(f"/boards/{BOARD_ID}/labels", {})
    label_ids = {
        "Alta":  next((lb["id"] for lb in labels if lb.get("color") == "red"), None),
        "Média": next((lb["id"] for lb in labels if lb.get("color") == "yellow"), None),
        "Baixa": next((lb["id"] for lb in labels if lb.get("color") == "green"), None),
    }
    print("[TRELLO] LIST_ID:", list_id)
    print("[TRELLO] LABEL_IDS:", label_ids)
    return list_id, label_ids


# Resolve referências ao iniciar (falha cedo se credenciais/IDs inválidos)
LIST_ID, LABEL_IDS = get_board_refs()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/salvar", methods=["POST"])
def salvar():
    data = request.json or {}

    # Campos
    nome          = (data.get("nome") or "").strip()
    contato       = (data.get("contato") or "").strip()
    representante = (data.get("representante") or "").strip()
    suporte       = (data.get("suporte") or "").strip()
    sistema       = (data.get("sistema") or "").strip()
    modulo        = (data.get("modulo") or "").strip()
    ocorrencia    = (data.get("ocorrencia") or "").strip()
    tipo          = (data.get("tipo") or "").strip()             # NOVO: Tipo (Dúvida/Melhoria/Bug)
    descricao     = (data.get("descricao") or "").strip()
    observacao    = (data.get("observacao") or "").strip()
    prioridade    = (data.get("prioridade") or "").strip()

    # Obrigatórios (inclui tipo e descricao)
    obrig = [nome, contato, representante, suporte, sistema, modulo, ocorrencia, tipo, descricao, prioridade]
    if not all(obrig):
        return jsonify(success=False, message="Campos obrigatórios faltando."), 400

    # Normalizações simples
    nome = nome.title()
    suporte = suporte.title()

    titulo = f"{nome} - {sistema} ({ocorrencia})"
    desc = (
        f"**Nome:** {nome}\n"
        f"**Contato:** {contato}\n"
        f"**Representante:** {representante}\n"
        f"**Suporte:** {suporte}\n"
        f"**Sistema:** {sistema}\n"
        f"**Módulo:** {modulo}\n"
        f"**Ocorrência:** {ocorrencia}\n"
        f"**Tipo:** {tipo}\n"
        f"**Prioridade:** {prioridade}\n\n"
        f"**Descrição/Solicitação:**\n{descricao or '-'}\n\n"
        f"**Observação:**\n{observacao or '-'}\n"
    )

    params = {"idList": LIST_ID, "name": titulo, "desc": desc}
    if LABEL_IDS.get(prioridade):
        params["idLabels"] = LABEL_IDS[prioridade]

    try:
        trello_post("/cards", params)
        return jsonify(success=True, message="Chamado criado com sucesso no Trello!")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
