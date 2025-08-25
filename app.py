from flask import Flask, render_template, request, jsonify, send_from_directory, abort, make_response
import requests
import os
import json
import hashlib
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ===================== CONFIG TRELLO (via variáveis de ambiente) =====================
# Defina no ambiente: TRELLO_KEY, TRELLO_TOKEN, (opcional) TRELLO_BOARD, TRELLO_LIST
API_KEY   = os.getenv("TRELLO_KEY", "")
TOKEN     = os.getenv("TRELLO_TOKEN", "")
BOARD_ID  = os.getenv("TRELLO_BOARD", "fGQqUBuw")  # shortLink do board por padrão
LIST_NAME = os.getenv("TRELLO_LIST", "Chamados abertos")
# =====================================================================================

TRELLO_BASE = "https://api.trello.com/1"
TIMEOUT = 15  # segundos

# ====== Caminhos para download do aplicativo ======
BASE_DIR = Path(__file__).resolve().parent
DOWNLOADS_DIR = BASE_DIR / "downloads"
MANIFEST = DOWNLOADS_DIR / "latest.json"
# ==================================================

# ====== Extensões permitidas para anexos ======
ALLOWED_EXT = {
    "png","jpg","jpeg","gif","webp",      # imagens
    "pdf","txt","csv","xlsx","xls","doc","docx",  # documentos
    "zip","rar","7z"                       # compactados
}
def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT
# ===============================================


def trello_get(path: str, params: dict):
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


def trello_attach_file(card_id: str, filename: str, fileobj, mimetype: str = None):
    url = f"{TRELLO_BASE}/cards/{card_id}/attachments"
    files = {"file": (filename, fileobj, mimetype or "application/octet-stream")}
    p = {"key": API_KEY, "token": TOKEN}
    r = requests.post(url, params=p, files=files, timeout=60)
    if not r.ok:
        print("[TRELLO][ATTACH] Falha:", r.status_code, r.text[:300])


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
    # Só mostra botão de download se não for localhost (ou 127.0.0.1)
    is_web = not (request.host.startswith("localhost") or request.host.startswith("127.0.0.1"))
    return render_template("index.html", show_download=is_web)


@app.route("/salvar", methods=["POST"])
def salvar():
    """
    Recebe dados via multipart/form-data (FormData do front) ou JSON.
    Cria o card no Trello e anexa arquivos (campo 'anexos').
    """
    data = request.form if request.form else (request.json or {})

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

    params = {"idList": LIST_ID, "name": titulo, "desc": desc}

    # Aplica label de prioridade, se existir no board
    label_id = LABEL_IDS.get(prioridade)
    if label_id:
        params["idLabels"] = label_id

    try:
        card = trello_post("/cards", params=params)
        card_id = card.get("id")

        # Anexos (campo 'anexos' no FormData; múltiplos)
        if request.files:
            arquivos = request.files.getlist("anexos")
            for f in arquivos:
                if not f or not f.filename:
                    continue
                filename = secure_filename(f.filename)
                if not _allowed(filename):
                    print(f"[ANEXO] Ignorado (extensão não permitida): {filename}")
                    continue
                trello_attach_file(card_id, filename, f.stream, f.mimetype)

        return jsonify(success=True, message="Chamado criado com sucesso no Trello!")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400


# ===================== Download do aplicativo =====================

def _compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_data():
    if not MANIFEST.exists():
        raise RuntimeError("downloads/latest.json não encontrado.")
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    fname = data.get("filename")
    if not fname:
        raise RuntimeError("Campo 'filename' ausente no latest.json.")
    file_path = DOWNLOADS_DIR / fname
    if not file_path.exists():
        raise RuntimeError(f"Arquivo da versão não encontrado: {fname}")
    if not data.get("sha256"):
        data["sha256"] = _compute_sha256(file_path)
    if not data.get("size_bytes"):
        data["size_bytes"] = file_path.stat().st_size
    return data


@app.route("/baixar")
def baixar():
    try:
        data = _manifest_data()
        filename = data["filename"]
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

    resp = make_response(send_from_directory(
        directory=str(DOWNLOADS_DIR),
        path=filename,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
        conditional=True
    ))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/downloads/<path:filename>")
def baixar_versionado(filename):
    file_path = DOWNLOADS_DIR / filename
    if not file_path.exists():
        abort(404)
    resp = make_response(send_from_directory(
        directory=str(DOWNLOADS_DIR),
        path=filename,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
        conditional=True
    ))
    resp.headers["Cache-Control"] = "public, max-age=604800, immutable"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/versao.json")
def versao_json():
    try:
        data = _manifest_data()
        return jsonify({
            "version": data.get("version"),
            "filename": data.get("filename"),
            "sha256": data.get("sha256"),
            "size_bytes": data.get("size_bytes"),
            "notes": data.get("notes", "")
        })
    except Exception as e:
        return jsonify(error=str(e)), 500


# ================================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
