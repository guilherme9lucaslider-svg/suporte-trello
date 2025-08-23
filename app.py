from flask import Flask, render_template, request, jsonify
import requests
import os

app = Flask(__name__)

# ===================== CONFIG TRELLO (via variáveis de ambiente) =====================
# NUNCA deixe KEY/TOKEN hardcoded em código público. Configure como ENV VARS:
#   TRELLO_KEY, TRELLO_TOKEN, (opcional) TRELLO_BOARD, TRELLO_LIST
API_KEY   = os.getenv("TRELLO_KEY", "")
TOKEN     = os.getenv("TRELLO_TOKEN", "")
BOARD_ID  = os.getenv("TRELLO_BOARD", "fGQqUBuw")  # shortLink do board por padrão
LIST_NAME = os.getenv("TRELLO_LIST", "Chamados abertos")
# =====================================================================================

TRELLO_BASE = "https://api.trello.com/1"
TIMEOUT = 15  # segundos


def trello_get(path: str, params: dict):
    """GET com checagem de erro e mensagens claras."""
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    url = f"{TRELLO_BASE}{path}"
    resp = requests.get(url, params=p, timeout=TIMEOUT)
    if not resp.ok:
        raise RuntimeError(f"[TRELLO][GET {path}] {resp.status_code}: {resp.text[:300]}")
    try:
        return resp.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][GET {path}] Resposta não é JSON: {resp.text[:300]}")


def trello_post(path: str, params: dict):
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    url = f"{TRELLO_BASE}{path}"
    resp = requests.post(url, params=p, timeout=TIMEOUT)
    if not resp.ok:
        raise RuntimeError(f"[TRELLO][POST {path}] {resp.status_code}: {resp.text[:300]}")
    try:
        return resp.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][POST {path}] Resposta não é JSON: {resp.text[:300]}")


def get_board_refs():
    if not API_KEY or not TOKEN:
        raise RuntimeError("[CONFIG] Defina TRELLO_KEY e TRELLO_TOKEN nas variáveis de ambiente.")

    # Descobrir ID da lista desejada
    lists = trello_get(f"/boards/{BOARD_ID}/lists", params={})
    list_id = next((l["id"] for l in lists if l.get("name") == LIST_NAME), None)
    if not list_id:
        nomes = ", ".join(l.get("name", "?") for l in lists)
        raise RuntimeError(f'[TRELLO] Lista "{LIST_NAME}" não encontrada. Disponíveis: {nomes}')

    # Mapear labels por cor
    labels = trello_get(f"/boards/{BOARD_ID}/labels", params={})
    label_ids = {
        "Alta":  next((lb["id"] for lb in labels if lb.get("color") == "red"), None),
        "Média": next((lb["id"] for lb in labels if lb.get("color") == "yellow"), None),
        "Baixa": next((lb["id"] for lb in labels if lb.get("color") == "green"), None),
    }

    print("[TRELLO] LIST_ID:", list_id)
    print("[TRELLO] LABEL_IDS:", label_ids)
    return list_id, label_ids


# Resolve referências ao iniciar o app (falha cedo se houver problema de permissão/ID)
LIST_ID, LABEL_IDS = get_board_refs()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/salvar", methods=["POST"])
def salvar():
    data = request.json or {}

    nome          = (data.get("nome") or "").strip()
    contato       = (data.get("contato") or "").strip()
    representante = (data.get("representante") or "").strip()
    suporte       = (data.get("suporte") or "").strip()
    sistema       = (data.get("sistema") or "").strip()
    modulo        = (data.get("modulo") or "").strip()
    ocorrencia    = (data.get("ocorrencia") or "").strip()
    descricao     = (data.get("descricao") or "").strip()
    observacao    = (data.get("observacao") or "").strip()
    prioridade    = (data.get("prioridade") or "").strip()

    obrig = [nome, contato, representante, suporte, sistema, modulo, ocorrencia, prioridade]
    if not all(obrig):
        return jsonify(success=False, message="Campos obrigatórios faltando."), 400

    titulo = f"{nome} - {sistema} ({ocorrencia})"
    desc = (
        f"**Nome:** {nome}\n"
        f"**Contato:** {contato}\n"
        f"**Representante:** {representante}\n"
        f"**Suporte:** {suporte}\n"
        f"**Sistema:** {sistema}\n"
        f"**Módulo:** {modulo}\n"
        f"**Ocorrência:** {ocorrencia}\n"
        f"**Prioridade:** {prioridade}\n\n"
        f"**Descrição/Solicitação:**\n{descricao or '-'}\n\n"
        f"**Observação:**\n{observacao or '-'}\n"
    )

    params = {
        "idList": LIST_ID,
        "name": titulo,
        "desc": desc,
    }

    # Aplica label de prioridade, se existir no board
    label_id = LABEL_IDS.get(prioridade)
    if label_id:
        params["idLabels"] = label_id

    try:
        _ = trello_post("/cards", params=params)
        return jsonify(success=True, message="Chamado criado com sucesso no Trello!")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
