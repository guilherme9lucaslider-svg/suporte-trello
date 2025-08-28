# app.py (substituir integralmente)

from flask import Response
import os
import json
import hashlib
import sys
import re
import time
from pathlib import Path
from datetime import datetime

from functools import wraps
from flask import (
    Flask, render_template, request, jsonify, send_from_directory,
    abort, make_response, session, redirect, url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests

# -----------------------------------------------------------------------------
# Paths / App
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "super-secret-key")  # troque em produção
# Não manter sessões permanentes: o usuário deverá fazer login novamente
app.config["SESSION_PERMANENT"] = False
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# -----------------------------------------------------------------------------
# Database (SQLite + SQLAlchemy)
# -----------------------------------------------------------------------------
DB_PATH = os.getenv("USERS_DB_PATH") or str((BASE_DIR / "users.db").resolve())
db_uri = os.getenv("DATABASE_URL")
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri or f"sqlite:///{DB_PATH}"

db = SQLAlchemy(app)

class Representative(db.Model):
    __tablename__ = "representatives"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    representative_id = db.Column(db.Integer, db.ForeignKey("representatives.id"), nullable=False)
    representative = db.relationship("Representative", backref="users")

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

with app.app_context():
    db.create_all()
    # Seed representatives se vazio (lista do seu projeto)
    if Representative.query.count() == 0:
        PRESET_REPS = [
            "Host.com","2RTI Soluções","MT Solutions","Unai System","Multitech",
            "Mad Automação","Tecnuve Soluções","GoSystem Automação","RJ Soluções",
            "Raizes Tecnologia","Webside Sistemas","Web System Norte","Online Soluções",
            "Delane","Supriserv","MS Tech Soluções","Use Tecnologia","Unity Automação",
            "Digital RF Tecnologia","Connecta Informática","R.A Soluções"
        ]
        for name in PRESET_REPS:
            db.session.add(Representative(name=name))
        db.session.commit()

# -----------------------------------------------------------------------------
# Admin helpers
# -----------------------------------------------------------------------------
ADMIN_USER = os.getenv("ADMIN_USER", "lider")
ADMIN_PASS = os.getenv("ADMIN_PASS", "2018")

def admin_logged():
    return session.get("admin") is True

def serialize_rep(rep):
    return {"id": rep.id, "name": rep.name}

def serialize_user(u):
    return {
        "id": u.id,
        "username": u.username,
        "representative": u.representative.name if u.representative else None,
        "representative_id": u.representative_id,
    }

def wants_json():
    xr = request.headers.get('X-Requested-With','')
    if xr.lower() == 'xmlhttprequest':
        return True
    accept = request.headers.get('Accept','')
    return 'application/json' in accept

# -----------------------------------------------------------------------------
# Trello / Downloads / Configs diversas
# -----------------------------------------------------------------------------
API_KEY   = os.getenv("TRELLO_KEY", "")
TOKEN     = os.getenv("TRELLO_TOKEN", "")
BOARD_ID  = os.getenv("TRELLO_BOARD", "fGQqUBuw")
LIST_NAME = os.getenv("TRELLO_LIST", "Chamados abertos")
TRELLO_BASE = "https://api.trello.com/1"

# Resolve automaticamente o LIST_ID (env TRELLO_LIST_ID > busca por nome no board)
def get_list_id():
    lid = app.config.get('TRELLO_LIST_ID')
    if lid:
        return lid
    lid = os.getenv("TRELLO_LIST_ID")
    if lid:
        app.config['TRELLO_LIST_ID'] = lid
        return lid
    try:
        resp = requests.get(
            f"{TRELLO_BASE}/boards/{BOARD_ID}/lists",
            params={"key": API_KEY, "token": TOKEN},
            timeout=15
        )
        if resp.ok:
            for lst in resp.json():
                if (lst.get("name","") or "").lower() == LIST_NAME.lower():
                    lid = lst.get("id")
                    if lid:
                        app.config['TRELLO_LIST_ID'] = lid
                        return lid
        print(f"[WARN] Lista '{LIST_NAME}' não encontrada no board {BOARD_ID}.")
    except Exception as e:
        print("[WARN] Falha ao resolver LIST_ID:", e)
    return None

try:
    LABEL_IDS = json.loads(os.getenv("TRELLO_LABELS","{}"))
    if not isinstance(LABEL_IDS, dict):
        LABEL_IDS = {}
except Exception:
    LABEL_IDS = {}

DOWNLOADS_DIR = BASE_DIR / "downloads"
MANIFEST = DOWNLOADS_DIR / "latest.json"
HIDE_DOWNLOAD_BUTTON = (os.getenv("HIDE_DOWNLOAD_BUTTON", "0") == "1")
IS_DESKTOP = bool(getattr(sys, "frozen", False)) or os.getenv("APP_DESKTOP") == "1"
ALLOWED_EXT = {"png","jpg","jpeg","gif","webp","pdf","txt","csv","xlsx","xls","doc","docx","zip","rar","7z"}

LIST_STATUS_MAP = {
    "Chamados abertos": "Em aberto",
    "Em análise": "Em análise",
    "Aguardando versão": "Aguardando versão",
    "Abrir requisição": "Aguardando Requisição",
    "Resolvidos": "Finalizado",
    "Descartados": "Descartado",
}

def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def trello_get(path: str, params: dict):
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    r = requests.get(f"{TRELLO_BASE}{path}", params=p, timeout=15)
    if not r.ok:
        raise RuntimeError(f"[TRELLO][GET {path}] {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][GET {path}] Resposta não é JSON: {r.text[:300]}")

_trello_cache: dict = {}
def cached_trello_get(path: str, params: dict, ttl: int = 5):
    key = (path, tuple(sorted((params or {}).items())))
    now = time.monotonic()
    entry = _trello_cache.get(key)
    if entry:
        age = now - entry[1]
        if age < ttl:
            return entry[0]
    value = trello_get(path, params)
    _trello_cache[key] = (value, now)
    return value

def trello_post(path: str, params: dict):
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    r = requests.post(f"{TRELLO_BASE}{path}", params=p, timeout=15)
    if not r.ok:
        raise RuntimeError(f"[TRELLO][POST {path}] {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"[TRELLO][POST {path}] Resposta não é JSON: {r.text[:300]}")

def trello_attach_file(card_id: str, filename: str, fileobj, mimetype: str = None):
    url = f"{TRELLO_BASE}/cards/{card_id}/attachments"
    files = {"file": (filename, fileobj, mimetype or "application/octet-stream")}
    p = {"key": API_KEY, "token": TOKEN}
    r = requests.post(url, params=p, files=files, timeout=60)
    if not r.ok:
        print("[TRELLO][ATTACH] Falha:", r.status_code, r.text[:300])

def trello_clear_cover(card_id: str):
    try:
        url = f"{TRELLO_BASE}/cards/{card_id}/cover"
        r = requests.put(
            url,
            params={"key": API_KEY, "token": TOKEN},
            json={"idAttachment": None},
            timeout=15
        )
        if not r.ok:
            print("[TRELLO][COVER] Falha ao remover capa:", r.status_code, r.text[:300])
    except Exception as e:
        print("[TRELLO][COVER] Exceção ao remover capa:", e)

# -----------------------------------------------------------------------------
# Auth Guard (público: painel e API; cadastro exige login; admin exige admin)
# -----------------------------------------------------------------------------
@app.before_request
def _auth_guard():
    path = request.path or "/"
    # Público (sem sessão de user/admin)
    if (
        path.startswith("/static/") or
        path in {"/static", "/sw.js", "/versao.json", "/favicon.ico"} or
        path.startswith("/baixar") or
        path.startswith("/downloads") or
        path.startswith("/api/chamados") or
        path.startswith("/api/representantes") or
        path == "/login" or
        path.startswith("/admin/login")
    ):
        return

    # Admin (rotas /admin/*)
    if path.startswith("/admin"):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return

    # Demais rotas (ex.: "/") exigem usuário logado (ou admin logado)
    if not session.get("user") and not session.get("admin"):
        return redirect(url_for("login"))
    # Bloqueio de /painel direto por admin sem user (caso de iframe antigo)
    if path == "/painel" and session.get("admin") and not session.get("user"):
        ref = request.headers.get("Referer", "") or ""
        if "/admin" not in ref:
            return redirect(url_for("admin_home"))

# -----------------------------------------------------------------------------
# Páginas principais (usuário)
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    # exige login fresco para abrir o cadastro
    if not session.get('user') or not session.pop('fresh_cadastro', None):
        return redirect(url_for('login'))
    show_download = (not IS_DESKTOP) and (not HIDE_DOWNLOAD_BUTTON)
    rep = session.get("representante", "")
    reps = []
    if session.get('admin') and not rep:
        reps = Representative.query.order_by(Representative.name.asc()).all()
    return render_template("index.html", show_download=show_download, representante_logado=rep, reps=reps)

@app.route("/painel")
def painel():
    return render_template("painel.html")

def _parse_rep_from_desc(desc: str) -> str:
    if not desc:
        return ""
    m = re.search(r"\*\*Representante:\*\*\s*(.+)", desc)
    return (m.group(1).strip() if m else "").strip()

def _iso_date_only(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

@app.route("/api/chamados")
def api_chamados():
    f_rep   = (request.args.get("representante") or "").strip()
    f_stat  = (request.args.get("status") or "").strip()
    f_de    = _iso_date_only(request.args.get("de") or "")
    f_ate   = _iso_date_only(request.args.get("ate") or "")
    f_q     = (request.args.get("q") or "").strip().lower()

    # Força o filtro do representante para usuário comum
    if session.get('user') and not session.get('admin'):
        f_rep = session.get('representante', '').strip()

    lists = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={})
    id_to_list = {l["id"]: l.get("name", "") for l in lists}

    cards = cached_trello_get(
        f"/boards/{BOARD_ID}/cards",
        params={
            "fields": "name,desc,idList,dateLastActivity,shortUrl",
            "attachments": "false",
            "members": "false"
        }
    )

    items = []
    for c in cards:
        titulo = c.get("name","").strip()
        desc   = c.get("desc","") or ""
        lista  = id_to_list.get(c.get("idList",""), "")
        status = LIST_STATUS_MAP.get(lista, "Em aberto")
        url    = c.get("shortUrl")
        dt_raw = c.get("dateLastActivity")
        ultima = dt_raw

        representante = _parse_rep_from_desc(desc)

        if f_rep and representante != f_rep:
            continue
        if f_stat and status != f_stat:
            continue

        if (f_de or f_ate) and dt_raw:
            try:
                d = datetime.fromisoformat(dt_raw.replace("Z","+00:00")).date()
                if f_de and d < f_de:
                    continue
                if f_ate and d > f_ate:
                    continue
            except Exception:
                pass

        if f_q:
            base = (titulo + "\n" + desc).lower()
            if f_q not in base:
                continue

        items.append({
            "titulo": titulo,
            "descricao": desc,
            "representante": representante,
            "lista": lista,
            "status": status,
            "url": url,
            "ultima_atividade": ultima,
        })

    return jsonify({"total": len(items), "items": items})


@app.route("/api/representantes")
def api_representantes():
    """
    Endpoint público para retornar a lista de representantes cadastrados.
    Retorna um array de strings com os nomes em ordem alfabética. Isso
    permite que o front‑end preencha selects dinamicamente sem manter
    listas duplicadas no JavaScript.
    """
    reps = Representative.query.order_by(Representative.name.asc()).all()
    return jsonify([r.name for r in reps])

# -----------------------------------------------------------------------------
# Login / Logout (USUÁRIO)
# -----------------------------------------------------------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=None)

    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session.clear()
        session['user'] = username
        session['representante'] = user.representative.name
        session['fresh_cadastro'] = True
        return redirect(url_for('index'))

    return render_template('login.html', error='Usuário ou senha inválidos.')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -----------------------------------------------------------------------------
# Salvar chamado (formulário)
# -----------------------------------------------------------------------------
@app.route("/salvar", methods=["POST"])
def salvar():
    data = request.form if request.form else (request.json or {})
    nome          = (data.get("nome") or "").strip()
    contato       = (data.get("contato") or "").strip()
    representante = ((session.get('representante') or data.get('representante') or '')).strip()
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
    # Validação simples de contato: exigir ao menos 3 caracteres e conter número ou '@'
    if len(contato) < 3 or (not any(c.isdigit() for c in contato) and '@' not in contato):
        return jsonify(success=False, message="Informe um telefone ou e‑mail válido no campo Contato."), 400

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

    lid = get_list_id()
    if not lid:
        return jsonify(success=False, message="LIST_ID não configurado. Ajuste TRELLO_LIST/TRELLO_LIST_ID."), 500

    params = {"idList": lid, "name": titulo, "desc": desc}
    label_id = LABEL_IDS.get(prioridade)
    if label_id:
        params["idLabels"] = label_id

    try:
        card = trello_post("/cards", params=params)
        card_id = card.get("id")

        if request.files:
            for f in request.files.getlist("anexos"):
                if not f or not f.filename:
                    continue
                if not _allowed(f.filename):
                    continue
                trello_attach_file(card_id, secure_filename(f.filename), f.stream, f.mimetype)

        trello_clear_cover(card_id)
        return jsonify(success=True, message="Chamado criado com sucesso no Trello!")
    except Exception as e:
        # Erros de rede ou da API do Trello são capturados e exibidos de forma amigável.
        err_msg = str(e)
        # Remover partes sensíveis da mensagem que contenham tokens ou chaves.
        err_msg = re.sub(r"[A-Za-z0-9]{32,}", "***", err_msg)
        return jsonify(success=False, message=f"Falha ao criar o chamado: {err_msg}"), 400

# -----------------------------------------------------------------------------
# Downloads / versão
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Admin (rotas) – agora usando console.html como tela principal
# -----------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html", error=None)
    u = request.form.get("username","")
    p = request.form.get("password","")
    if u == ADMIN_USER and p == ADMIN_PASS:
        session.clear()
        session["admin"] = True
        session["fresh_admin"] = True
        return redirect(url_for("admin_home"))
    return render_template("admin_login.html", error="Credenciais inválidas.")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

@app.route("/admin")
def admin_home():
    # exige login fresco para abrir o admin
    if not session.get('admin') or not session.pop('fresh_admin', None):
        return redirect(url_for('admin_login'))
    if not admin_logged():
        return redirect(url_for("admin_login"))
    reps = Representative.query.order_by(Representative.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    # Agora o admin usa o layout do console.html
    resp = make_response(render_template("console.html", reps=reps, users=users))
    return _no_store(resp)

@app.route("/admin/rep/new", methods=["POST"])
def admin_rep_new():
    if not admin_logged():
        return redirect(url_for("admin_login"))
    name = (request.form.get("name") or "").strip()
    created = False
    if name and not Representative.query.filter_by(name=name).first():
        db.session.add(Representative(name=name))
        db.session.commit()
        created = True
    if wants_json():
        reps = [serialize_rep(r) for r in Representative.query.order_by(Representative.name.asc()).all()]
        return jsonify(ok=True, created=created, reps=reps)
    return redirect(url_for("admin_home"))

@app.route("/admin/rep/<int:rep_id>/delete", methods=["POST"])
def admin_rep_del(rep_id):
    if not admin_logged():
        return redirect(url_for("admin_login"))
    rep = Representative.query.get_or_404(rep_id)
    deleted = False
    if not rep.users:
        db.session.delete(rep)
        db.session.commit()
        deleted = True
    if wants_json():
        reps = [serialize_rep(r) for r in Representative.query.order_by(Representative.name.asc()).all()]
        return jsonify(ok=True, deleted=deleted, reps=reps)
    return redirect(url_for("admin_home"))

@app.route("/admin/user/new", methods=["POST"])
def admin_user_new():
    if not admin_logged():
        return redirect(url_for("admin_login"))
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    rep_id = request.form.get("representative_id")
    created = False
    if username and password and rep_id:
        rep = Representative.query.get(int(rep_id))
        exists = User.query.filter_by(username=username).first()
        if rep and not exists:
            u = User(username=username, representative=rep)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            created = True
    if wants_json():
        users = [serialize_user(u) for u in User.query.order_by(User.username.asc()).all()]
        return jsonify(ok=True, created=created, users=users)
    return redirect(url_for("admin_home"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
def admin_user_del(user_id):
    if not admin_logged():
        return redirect(url_for("admin_login"))
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    if wants_json():
        users = [serialize_user(u) for u in User.query.order_by(User.username.asc()).all()]
        return jsonify(ok=True, deleted=True, users=users)
    return redirect(url_for("admin_home"))

# -----------------------------------------------------------------------------
# Compat / antigo /console -> agora redireciona para /admin
# -----------------------------------------------------------------------------
@app.route("/console")
def console_redirect():
    return redirect(url_for("admin_home"))

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
