# app.py

# --- Standard Library ---
import os
import re
import time
import json
import io
import csv
import unicodedata
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import quote_plus

# --- Third-Party ---
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    make_response,
    render_template,
    request,
    session,
    redirect,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
import pandas as pd

load_dotenv()

# -----------------------------------------------------------------------------
# Add
# -----------------------------------------------------------------------------

IS_DESKTOP = os.getenv("APP_DESKTOP", "0") == "1"

# -----------------------------------------------------------------------------
# Paths / App
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# CSRF
csrf = CSRFProtect()
csrf.init_app(app)

# ==== Mostrar/ocultar botão "Baixar aplicativo" ====
def _compute_show_download(req=None):
    """Retorna True se o botão 'Baixar aplicativo' deve aparecer."""
    try:
        req = req or request
        ua = (req.headers.get("User-Agent") or "").lower()
    except Exception:
        ua = ""
    is_electron = "electron" in ua
    hide = (
        os.getenv("HIDE_DOWNLOAD_BUTTON", "0") == "1"
        or os.getenv("APP_DESKTOP", "0") == "1"
    )
    return not (is_electron or hide)


@app.context_processor
def inject_show_download():
    return {"show_download": _compute_show_download()}

@app.context_processor
def inject_csrf_token():
    # Permite usar {{ csrf_token() }} nos templates
    return {"csrf_token": generate_csrf}

@app.after_request
def set_csrf_cookie(resp):
    # Fornece o token também via cookie para facilitar uso em fetch (JS)
    try:
        token = generate_csrf()
        resp.set_cookie("csrf_token", token, httponly=False, samesite="Lax")
    except Exception:
        pass
    return resp


app.secret_key = os.getenv("APP_SECRET")
if not app.secret_key:
    raise RuntimeError("APP_SECRET não definido no ambiente.")
# Não manter sessões permanentes: o usuário deverá fazer login novamente
app.config["SESSION_PERMANENT"] = False
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# -----------------------------------------------------------------------------
# Database configuration
#
# Use a DATABASE_URL environment variable if provided, otherwise default to
# the remote PostgreSQL database provided by the user.  The password may
# contain special characters such as '@', so we percent‑encode it to form
# a valid URI.
db_uri = os.getenv("DATABASE_URL")
sslmode = os.getenv("DB_SSLMODE")

if not db_uri:
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASS")
    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_port = os.getenv("DB_PORT", "5432")

    missing = [k for k, v in {
        "DB_USER": db_user,
        "DB_PASS": db_password,
        "DB_HOST": db_host,
        "DB_NAME": db_name,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Variáveis ausentes: {', '.join(missing)}")

    # Percent‑encode special characters in the password.
    db_password_quoted = quote_plus(db_password)
    db_uri = f"postgresql://{db_user}:{db_password_quoted}@{db_host}:{db_port}/{db_name}"
if sslmode and "sslmode=" not in db_uri:
    db_uri += ("&" if "?" in db_uri else "?") + f"sslmode={sslmode}"
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri

# Configurações de pool de conexão para resolver problemas de desconexão
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 10,
    "pool_timeout": 20,
    "pool_recycle": 300,  # Recicla conexões a cada 5 minutos
    "pool_pre_ping": True,  # Testa conexões antes de usar
    "max_overflow": 20
}

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Database models
#
# A Representative (representante) has many Users (usuarios).  Each User is
# linked to exactly one Representative via the representante_id foreign key.
class Representative(db.Model):
    __tablename__ = "representantes"
    id = db.Column(db.Integer, primary_key=True)
    # 'nome' is unique to avoid duplicates.
    nome = db.Column(db.String(255), nullable=False, unique=True)
    # Relationship to users: cascade deletions so that removing a representative
    # will also remove its users (but the admin UI prevents deletion when users
    # exist).
    users = db.relationship(
        "User", back_populates="representative", cascade="all, delete-orphan"
    )


class User(db.Model):
    __tablename__ = "usuarios"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)

    # Hash para login seguro
    password_hash = db.Column(db.String(255), nullable=False)

    # NOVO: senha crua (coluna que você já criou no banco)
    password = db.Column(db.Text, nullable=True)

    representante_id = db.Column(
        db.Integer, db.ForeignKey("representantes.id"), nullable=False
    )
    representative = db.relationship("Representative", back_populates="users")

    def set_password(self, raw_password: str) -> None:
        """Define tanto o hash (para login) quanto a senha crua (para exibir no admin)."""
        self.password_hash = generate_password_hash(raw_password)
        self.password = raw_password  # grava a senha original na nova coluna

    def check_password(self, raw_password: str) -> bool:
        try:
            if not self.password_hash:
                return False
            return check_password_hash(self.password_hash, raw_password)
        except Exception:
            # Em caso de hash corrompido ou formato inválido, falha fechada
            return False


def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Admin helpers
# -----------------------------------------------------------------------------
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")

# Aviso inicial caso credenciais de admin não estejam definidas (não quebra o app)
if not ADMIN_USER or not ADMIN_PASS:
    try:
        print("[WARN] Variáveis ADMIN_USER/ADMIN_PASS não definidas; login admin indisponível.")
    except Exception:
        pass

def _mask_secrets(text: str) -> str:
    """Mascara valores sensíveis conhecidos em logs/erros."""
    try:
        if not text:
            return text
        s = str(text)
        # Mascara valores específicos de env se existirem
        for key in [
            "TRELLO_KEY","TRELLO_TOKEN","APP_SECRET","DB_PASS","DATABASE_URL",
        ]:
            val = os.getenv(key)
            if val:
                s = s.replace(val, "***")
        # Mascara sequências longas (tokens) genéricas
        s = re.sub(r"[A-Za-z0-9_-]{24,}", "***", s)
        return s
    except Exception:
        return "***"

def _norm(s: str) -> str:
    s = s or ""
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")  # remove acentos
    return s.strip().lower()

def _strip_accents(s: str) -> str:
    s = s or ""
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")

def _normalize_tipo(s: str) -> str:
    # retorna: 'duvida', 'melhoria', 'bug' ou ''
    s = _strip_accents(s).strip().lower()
    if s in ("duvida",):
        return "duvida"
    if s in ("melhoria",):
        return "melhoria"
    if s in ("bug",):
        return "bug"
    return ""

_TIPO_RE = re.compile(r"^\*\*Tipo:\*\*\s*(.+)$", re.MULTILINE)

def _infer_tipo_fallback(titulo: str, descricao: str) -> str:
    """
    Se a linha '**Tipo:**' não existir (ou vier vazia), tenta deduzir
    por palavras-chave no título/descrição.
    """
    base = _strip_accents(f"{titulo} {descricao}".lower())
    if "duvida" in base:
        return "duvida"
    if "melhoria" in base:
        return "melhoria"
    if "bug" in base:
        return "bug"
    return ""



def admin_logged():
    return session.get("admin") is True


def serialize_rep(rep):
    # Return a simple representation using the column names defined above.
    # Use 'nome' instead of 'name' to reflect the Portuguese field.
    return {"id": rep.id, "nome": rep.nome}


def serialize_user(u):
    return {
        "id": u.id,
        "username": u.username,
        "representante": u.representative.nome if u.representative else None,
        "representante_id": u.representante_id,
        # NOVO: senha crua (pode ser string vazia se não existir)
        "password": u.password or ""
    }



def wants_json():
    xr = request.headers.get("X-Requested-With", "")
    if xr.lower() == "xmlhttprequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


# -----------------------------------------------------------------------------
# Trello / Downloads / Configs diversas
# -----------------------------------------------------------------------------
API_KEY = os.getenv("TRELLO_KEY", "")
TOKEN = os.getenv("TRELLO_TOKEN", "")
BOARD_ID = os.getenv("TRELLO_BOARD", "fGQqUBuw")
LIST_NAME = os.getenv("TRELLO_LIST", "Chamados abertos")
TRELLO_BASE = "https://api.trello.com/1"

# Resolve automaticamente o LIST_ID (env TRELLO_LIST_ID > busca por nome no board)
def get_list_id():
    lid = app.config.get("TRELLO_LIST_ID")
    if lid:
        return lid
    lid = os.getenv("TRELLO_LIST_ID")
    if lid:
        app.config["TRELLO_LIST_ID"] = lid
        return lid
    try:
        resp = requests.get(
            f"{TRELLO_BASE}/boards/{BOARD_ID}/lists",
            params={"key": API_KEY, "token": TOKEN},
            timeout=15,
        )
        if resp.ok:
            for lst in resp.json():
                if (lst.get("name", "") or "").lower() == LIST_NAME.lower():
                    lid = lst.get("id")
                    if lid:
                        app.config["TRELLO_LIST_ID"] = lid
                        return lid
        if app.debug:
            print(f"[WARN] Lista '{LIST_NAME}' não encontrada no board {BOARD_ID}.")
    except Exception as e:
        if app.debug:
            print("[WARN] Falha ao resolver LIST_ID:", e)
    return None


try:
    LABEL_IDS = json.loads(os.getenv("TRELLO_LABELS", "{}"))
    if not isinstance(LABEL_IDS, dict):
        LABEL_IDS = {}
except Exception:
    LABEL_IDS = {}
HIDE_DOWNLOAD_BUTTON = os.getenv("HIDE_DOWNLOAD_BUTTON", "0") == "1"
ALLOWED_EXT = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "pdf",
    "txt",
    "csv",
    "xlsx",
    "xls",
    "doc",
    "docx",
    "zip",
    "rar",
    "7z",
}

LIST_STATUS_MAP = {
    "Chamados abertos": "Em aberto",
    "Em análise": "Em análise",
    "Aguardando versão": "Aguardando versão",
    "Abrir requisição": "Aguardando Requisição",
    "Resolvidos": "Finalizado",
    "Descartados": "Descartado",
}

# Status string to Trello list name (inverse of LIST_STATUS_MAP).
# Used for moving cards between lists via the Trello API.
STATUS_TO_LIST_NAME = {v: k for k, v in LIST_STATUS_MAP.items()}


def _infer_created_from_trello_id(tid: str) -> str | None:
    """
    Given a Trello card ID (24 hex characters), infer the creation timestamp.
    Trello's IDs follow the MongoDB ObjectID format: the first 8 hex
    characters represent the epoch timestamp in seconds. This helper returns
    an ISO 8601 timestamp in UTC (with "Z" suffix) or None if the input
    cannot be parsed.
    """
    try:
        if not tid or len(tid) < 8:
            return None
        secs = int(tid[:8], 16)
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def trello_get(path: str, params: dict):
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    try:
        r = requests.get(
            f"{TRELLO_BASE}{path}", params=p, timeout=10
        )  # reduzir timeout
        if app.debug:
            print(f"[TRELLO][GET] {path} -> {r.status_code}")
        if not r.ok:
            raise RuntimeError(f"[TRELLO][GET {path}] {r.status_code}: {r.text[:300]}")
        return r.json()
    except requests.exceptions.Timeout:
        raise RuntimeError(f"[TRELLO][GET {path}] Timeout na requisição")
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"[TRELLO][GET {path}] Erro de conexão")
    except Exception as e:
        raise RuntimeError(f"[TRELLO][GET {path}] Erro: {str(e)}")


_trello_cache: dict = {}


def cached_trello_get(path: str, params: dict, ttl: int = 30):
    key = (path, tuple(sorted((params or {}).items())))
    now = time.monotonic()
    entry = _trello_cache.get(key)
    if entry:
        age = now - entry[1]
        if age < ttl:
            if app.debug:
                print(f"[CACHE] HIT {path} age={age:.1f}s")
            return entry[0]

    # Limpar cache muito antigo
    if len(_trello_cache) > 30:  # Reduzir limite
        cutoff = now - ttl  # Usar TTL simples
        old_keys = [k for k, v in _trello_cache.items() if v[1] < cutoff]
        for k in old_keys:
            _trello_cache.pop(k, None)
        if app.debug:
            print(f"[CACHE] Limpou {len(old_keys)} entradas antigas")

    if app.debug:
        print(f"[CACHE] MISS {path}")

    try:
        value = trello_get(path, params)
        _trello_cache[key] = (value, now)
        return value
    except Exception as e:
        if app.debug:
            print(f"[CACHE] Erro no Trello: {e}")
        if "lists" in path:
            return []
        elif "cards" in path:
            return []
        raise e


def trello_post(path: str, params: dict):
    p = {"key": API_KEY, "token": TOKEN}
    p.update(params or {})
    r = requests.post(f"{TRELLO_BASE}{path}", params=p, timeout=15)
    if app.debug:
        print(f"[TRELLO][POST] {path} -> {r.status_code}")
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
    if app.debug:
        print(f"[TRELLO][ATTACH] {filename} -> {r.status_code}")
    if not r.ok:
        print("[TRELLO][ATTACH] Falha:", r.status_code, r.text[:300])


def trello_clear_cover(card_id: str):
    try:
        url = f"{TRELLO_BASE}/cards/{card_id}/cover"
        r = requests.put(
            url,
            params={"key": API_KEY, "token": TOKEN},
            json={"idAttachment": None},
            timeout=15,
        )
        if app.debug:
            print(f"[TRELLO][COVER] clear -> {r.status_code}")
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
        path.startswith("/static/")
        or path in {"/static", "/sw.js", "/favicon.ico"}
        or path.startswith("/api/chamados")
        or path.startswith("/api/representantes")
        or path == "/login"
        or path.startswith("/admin/login")
        or path.startswith("/api/clientes") \
        or path.startswith("/api/sistemas") \
        or path.startswith("/api/modulos") \
        or path.startswith("/api/ocorrencias")
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
    if not session.get("user") or not session.pop("fresh_cadastro", None):
        return redirect(url_for("login"))
    show_download = (not IS_DESKTOP) and (not HIDE_DOWNLOAD_BUTTON)
    rep = session.get("representante", "")
    reps = []
    if session.get("admin") and not rep:
        # Order by 'nome' to list representatives alphabetically
        reps = Representative.query.order_by(Representative.nome.asc()).all()
    return render_template(
        "index.html", show_download=show_download, representante_logado=rep, reps=reps
    )


@app.route("/painel")
def painel_redirect():
    return redirect(url_for("admin_home"), code=308)


# ==== Helpers de WhatsApp ====
def _only_digits(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


def _parse_rep_from_desc(desc: str) -> str:
    """Extrai o nome do Representante da descrição do card.
    Aceita formatos com ou sem **, ex: '**Representante:** Fulano' ou 'Representante: Fulano'.
    Retorna string vazia se não encontrar.
    """
    if not desc:
        return ""
    # tenta com **Representante:** (markdown)
    m = re.search(r"\*\*\s*Representante\s*:\s*\*\*\s*(.+)", desc, flags=re.I)
    if not m:
        # fallback sem asteriscos
        m = re.search(r"Representante\s*:\s*(.+)", desc, flags=re.I)
    return (m.group(1).strip() if m else "").strip()

def _parse_cliente_from_desc(desc: str) -> str:
    """
    Extrai o nome do Cliente/Nome da descrição do card.
    Aceita '**Cliente:** X', '**Nome:** X' ou sem asteriscos.
    Pega só a primeira linha após o rótulo.
    """
    if not desc:
        return ""
    m = re.search(r"\*\*\s*(?:Cliente|Nome)\s*:\s*\*\*\s*(.+)", desc, flags=re.I)
    if not m:
        m = re.search(r"(?:Cliente|Nome)\s*:\s*(.+)", desc, flags=re.I)
    val = (m.group(1) if m else "").strip()
    return val.splitlines()[0].strip()





def _normalize_phone_br(raw: str) -> str:
    """
    Normaliza para E.164 BR sem o '+', ex.: 5511987654321.
    - remove não dígitos
    - garante DDI 55 quando vier 10/11 dígitos
    - injeta '9' após o DDD quando faltar (celular antigo)
    """
    d = _only_digits(raw).lstrip("0")
    if not d.startswith("55") and len(d) in (10, 11):
        d = "55" + d
    sem_ddi = d[2:] if d.startswith("55") else d
    if len(sem_ddi) == 10:  # faltou o 9 do celular
        d = "55" + sem_ddi[:2] + "9" + sem_ddi[2:]
    return d


def _parse_whatsapp_from_desc(desc: str) -> str:
    """
    Procura um WhatsApp no texto (padrão **Whatsapp:** ... ou número solto).
    Retorna normalizado (ex.: 5511987654321) ou ''.
    """
    text = desc or ""

    # 1) padrão explícito **Whatsapp:** ...
    m = re.search(r"\*\*?\s*whats?app\s*:\s*\**\s*([+()\d\-\s]{8,})", text, flags=re.I)
    if m:
        n = _normalize_phone_br(m.group(1))
        return n if re.fullmatch(r"\d{12,13}", n) else ""

    # 2) fallback: primeira sequência que parece telefone BR
    m2 = re.search(
        r"(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?(?:9?\s*\d{4})[-\s]?\d{4}", text, flags=re.I
    )
    if m2:
        n = _normalize_phone_br(m2.group(0))
        return n if re.fullmatch(r"\d{12,13}", n) else ""

    return ""

def _parse_field_from_desc(desc: str, label: str) -> str:
    """
    Extrai um campo textual da descrição do Trello.
    Aceita formatos com ou sem negrito, por ex:
    **Sistema:** WebLíder
    Sistema: WebLíder
    """
    text = desc or ""
    # 1) com negrito/asteriscos
    m = re.search(rf"\*\*?\s*{re.escape(label)}\s*:\s*\**\s*(.+)", text, flags=re.I)
    if m:
        return m.group(1).strip()
    # 2) simples
    m2 = re.search(rf"{re.escape(label)}\s*:\s*(.+)", text, flags=re.I)
    return (m2.group(1).strip() if m2 else "")

def _parse_sistema_from_desc(desc: str) -> str:
    return _parse_field_from_desc(desc, "Sistema")

def _parse_modulo_from_desc(desc: str) -> str:
    return _parse_field_from_desc(desc, "Módulo")

def _parse_ocorrencia_from_desc(desc: str) -> str:
    return _parse_field_from_desc(desc, "Ocorrência")
    
# regex que aceita "Tipo:" ou "Tipo de Chamado:"
_TIPO_REGEX = re.compile(
    r'(?:\*\*)?\s*tipo(?:\s*de\s*chamado)?\s*:\s*(.+)',
    re.IGNORECASE
)

def _parse_tipo_from_desc(desc: str) -> str:
    """
    Pega a linha '**Tipo:** ...' ou '**Tipo de Chamado:** ...' da descrição do card.
    Retorna normalizado: 'duvida' | 'melhoria' | 'bug' | ''.
    """
    if not desc:
        return ""
    m = _TIPO_REGEX.search(desc)  # usa o regex mais abrangente
    if not m:
        return ""
    bruto = (m.group(1) or "").strip()
    return _normalize_tipo(bruto)





# ---------------------------------------------------------------------------
# Nova implementação do endpoint /api/chamados com suporte a id, created_at,
# paginação via offset/limit e filtragem.


def _iso_date_only(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


@app.route("/api/chamados")
def api_chamados():
    f_cliente = (request.args.get("cliente") or "").strip().lower()
    f_sistema = (request.args.get("sistema") or "").strip().lower()
    f_modulo  = (request.args.get("modulo") or "").strip().lower()
    f_ocor    = (request.args.get("ocorrencia") or "").strip().lower()
    f_rep = (request.args.get("representante") or "").strip()
    f_stat = (request.args.get("status") or "").strip()
    f_tipo = (request.args.get("tipo") or "").strip()
    f_tipo_norm = _normalize_tipo(f_tipo)
    f_de = _iso_date_only(request.args.get("de") or "")
    f_ate = _iso_date_only(request.args.get("ate") or "")
    f_q = (request.args.get("q") or "").strip().lower()
    f_de_criacao  = _iso_date_only(request.args.get("de_criacao") or "")
    f_ate_criacao = _iso_date_only(request.args.get("ate_criacao") or "")

    # paginação

    try:
        offset = int(request.args.get("offset", "0"))
        if offset < 0:
            offset = 0
    except Exception:
        offset = 0
    try:
        limit = int(request.args.get("limit", "0"))
        if limit < 0:
            limit = 0
    except Exception:
        limit = 0

    # força representante para não-admin
    if session.get("user") and not session.get("admin"):
        f_rep = session.get("representante", "").strip()

    # credenciais Trello
    if not API_KEY or not TOKEN or not BOARD_ID:
        response = jsonify({"error":"Configuração do Trello incompleta","total":0,"items":[]})
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response, 500

    # listar listas e cards
    try:
        lists = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={})
        id_to_list = {l["id"]: l.get("name", "") for l in lists}
        cards = cached_trello_get(
            f"/boards/{BOARD_ID}/cards",
            params={
                "fields": "name,desc,idList,dateLastActivity,shortUrl,id",
                "attachments": "true",
                "members": "false",
            },
        )
    except Exception as e:
        if app.debug:
            print(f"[API] Erro Trello: {e}")
        response = jsonify({"error":"Erro ao conectar com Trello: "+str(e),"total":0,"items":[]})
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response, 500

    items = []
    for c in cards:
        titulo = (c.get("name") or "").strip()
        desc = c.get("desc") or ""
        lista_id = c.get("idList") or ""
        lista = id_to_list.get(lista_id, "")
        status = LIST_STATUS_MAP.get(lista, "Em aberto")
        url = c.get("shortUrl")
        dt_raw = c.get("dateLastActivity")  # ISO do Trello

        representante = _parse_rep_from_desc(desc)
        whats = _parse_whatsapp_from_desc(desc)
        cliente = _parse_cliente_from_desc(desc)

        # >>> extrai campos de formulário gravados na descrição
        sistema    = _parse_sistema_from_desc(desc)
        modulo     = _parse_modulo_from_desc(desc)
        ocorrencia = _parse_ocorrencia_from_desc(desc)

        # --- Tipo (normalizado) ---
        # 1) extrai da descrição (**Tipo:** ...) e normaliza
        tipo_bruto = _parse_tipo_from_desc(desc)
        tipo = _normalize_tipo(tipo_bruto)
        # 2) se vazio, tenta deduzir e normaliza
        if not tipo:
            tipo = _normalize_tipo(_infer_tipo_fallback(titulo, desc))
        # 3) filtro de tipo
        if f_tipo_norm and tipo != f_tipo_norm:
            continue

        # filtros
        if f_rep and representante != f_rep:
            continue
        if f_stat and status != f_stat:
            continue
        if f_cliente and f_cliente not in (cliente or "").lower():
            continue
        if f_sistema and _norm(f_sistema) != _norm(sistema):
            continue
        if f_modulo and _norm(f_modulo) != _norm(modulo):
            continue
        if f_ocor and _norm(f_ocor) != _norm(ocorrencia):
            continue

        # filtro por última atividade (de/ate)
        if (f_de or f_ate) and dt_raw:
            try:
                d = datetime.fromisoformat(dt_raw.replace("Z", "+00:00")).date()
                if f_de and d < f_de:
                    continue
                if f_ate and d > f_ate:
                    continue
            except Exception:
                pass

        # busca textual opcional
        if f_q:
            base = (titulo + "\n" + desc).lower()
            if f_q not in base:
                continue

        # inferir criação e aplicar filtro de criação apenas se AMBAS as datas vierem
        card_id = c.get("id")
        created_at = _infer_created_from_trello_id(card_id)
        if f_de_criacao and f_ate_criacao:
            try:
                created_date = (
                    datetime.fromisoformat(created_at.replace("Z", "+00:00")).date()
                    if created_at else None
                )
            except Exception:
                created_date = None
            if created_date:
                if created_date < f_de_criacao:
                    continue
                if created_date > f_ate_criacao:
                    continue

        # Processar todos os anexos (imagens e arquivos)
        attachments_raw = c.get("attachments", [])
        attachments = []
        images = []  # manter compatibilidade com código existente
        if attachments_raw:
            for att in attachments_raw:
                if att.get("isUpload"):
                    attachment_data = {
                        "id": att.get("id"),
                        "name": att.get("name"),
                        "url": att.get("url"),
                        "mimeType": att.get("mimeType", ""),
                        "previews": att.get("previews", [])
                    }
                    attachments.append(attachment_data)
                    
                    # Manter lista de imagens separada para compatibilidade
                    if att.get("mimeType", "").startswith("image/"):
                        images.append(attachment_data)

        items.append({
            "id": card_id,
            "titulo": titulo,
            "descricao": desc,
            "cliente": cliente,
            "representante": representante,
            "lista": lista,
            "status": status,
            "url": url,
            "ultima_atividade": dt_raw,
            "whatsapp": whats,
            "created_at": created_at,
            "sistema": sistema or None,
            "modulo": modulo or None,
            "ocorrencia": ocorrencia or None,
            "tipo": tipo or None,
            "images": images,
            "attachments": attachments,
        })

    # Ordena por última atividade em ordem decrescente (mais recentes primeiro)
    items.sort(key=lambda x: x.get("ultima_atividade", ""), reverse=True)
    
    total = len(items)
    paginated = items if not limit else items[offset: offset + limit]

    if app.debug:
        print(f"[API] /api/chamados -> {total} itens (retornando {len(paginated)})")

    response = jsonify({"total": total, "items": paginated})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response




# ---------------------------------------------
# Diagnostico
# ---------------------------------------------
@app.route("/api/diagnostico")
def api_diagnostico():
    """Endpoint para testar conectividade com Trello"""
    diagnostics = {
        "api_key_configured": bool(API_KEY),
        "token_configured": bool(TOKEN),
        "board_id_configured": bool(BOARD_ID),
        "trello_connection": False,
    }

    if not API_KEY or not TOKEN or not BOARD_ID:
        return jsonify(diagnostics)

    try:
        lists = trello_get(f"/boards/{BOARD_ID}/lists", {})
        diagnostics["trello_connection"] = True
        diagnostics["lists_count"] = len(lists)
        diagnostics["list_names"] = [l.get("name") for l in lists]
    except Exception as e:
        diagnostics["error"] = _mask_secrets(str(e))

    return jsonify(diagnostics)


# ---------------------------------------------------------------------------
# Endpoint para mudar o status (lista) de um card específico. Recebe JSON com
# {"status": "Novo Status"} e move o card para a lista correspondente no
# Trello. Apenas usuários autenticados podem realizar esta ação.
@csrf.exempt
@app.route("/api/chamados/<card_id>/status", methods=["POST"])
def api_chamados_change_status(card_id: str):
    if not card_id:
        return jsonify(success=False, message="Id do card ausente"), 400
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    new_status = (data.get("status") or "").strip()
    if not new_status:
        return jsonify(success=False, message="Status ausente"), 400
    # Resolve lista destino a partir do status
    dest_list_name = STATUS_TO_LIST_NAME.get(new_status)
    if not dest_list_name:
        return jsonify(success=False, message="Status inválido"), 400
    # Busca todas as listas do board para encontrar o id da lista destino
    try:
        lists = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={})
    except Exception:
        lists = []
    name_to_id = {lst.get("name"): lst.get("id") for lst in lists}
    dest_list_id = name_to_id.get(dest_list_name)
    if not dest_list_id:
        return jsonify(success=False, message="Lista destino não encontrada"), 400
    # Faz a requisição para mover o card
    try:
        resp = requests.put(
            f"{TRELLO_BASE}/cards/{card_id}",
            params={
                "idList": dest_list_id,
                "key": API_KEY,
                "token": TOKEN,
            },
            timeout=30,
        )
        if not resp.ok:
            return (
                jsonify(success=False, message="Falha ao mover card", detail=resp.text),
                500,
            )
    except Exception as e:
        return jsonify(success=False, message="Erro ao mover card", detail=str(e)), 500
    response = jsonify(success=True)
    return response


# ---------------------------------------------------------------------------
# Endpoint de streaming (Server-Sent Events) para monitoramento em tempo real.
# Envia um evento sempre que houver mudança na lista de cards (id ou última
# atividade). O cliente deve abrir uma EventSource neste endpoint. A verificação
# é feita em intervalos de 10 segundos usando o cache da API do Trello para
# minimizar requisições.
@app.route("/api/chamados/stream")
def api_chamados_stream():
    def event_stream():
        last_hash = None
        consecutive_errors = 0
        try:
            while True:
                try:
                    yield 'data: {"ping": true}\n\n'  # heartbeat
                    time.sleep(1)

                    cards = cached_trello_get(
                        f"/boards/{BOARD_ID}/cards",
                        params={
                            "fields": "idList,dateLastActivity,id",
                            "attachments": "false",
                            "members": "false",
                        },
                    )
                    consecutive_errors = 0  # reset contador de erros
                except Exception as e:
                    consecutive_errors += 1
                    if consecutive_errors > 3:
                        yield f'data: {{"error": "Muitos erros consecutivos"}}\n\n'
                        break
                    cards = []

                # Calcula hash para detectar mudanças
                try:
                    summary = [
                        {
                            "id": c.get("id"),
                            "idList": c.get("idList"),
                            "last": c.get("dateLastActivity"),
                        }
                        for c in cards
                    ]
                    new_hash = hashlib.md5(
                        json.dumps(summary, sort_keys=True).encode()
                    ).hexdigest()
                except Exception:
                    new_hash = None

                if last_hash is None:
                    last_hash = new_hash
                elif new_hash != last_hash:
                    last_hash = new_hash
                    yield f'data: {{"update": true}}\n\n'

                time.sleep(15)
        except GeneratorExit:
            # Cliente desconectou
            pass
        finally:
            # Cleanup final se necessário
            pass

    return Response(event_stream(), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Endpoint para exportar os chamados filtrados em CSV ou XLSX. Utiliza as
# mesmas regras de filtragem de /api/chamados. Por padrão retorna CSV.
@app.route("/api/chamados/export")
def api_chamados_export():
    fmt = (request.args.get("format") or "csv").lower()

    # filtros
    f_rep = (request.args.get("representante") or "").strip()
    f_stat = (request.args.get("status") or "").strip()
    f_de = _iso_date_only(request.args.get("de") or "")
    f_ate = _iso_date_only(request.args.get("ate") or "")
    f_q = (request.args.get("q") or "").strip().lower()
    f_de_criacao  = _iso_date_only(request.args.get("de_criacao") or "")
    f_ate_criacao = _iso_date_only(request.args.get("ate_criacao") or "")
    f_cliente = (request.args.get("cliente") or "").strip().lower()
    f_sistema = (request.args.get("sistema") or "").strip()
    f_modulo  = (request.args.get("modulo") or "").strip()
    f_ocor    = (request.args.get("ocorrencia") or "").strip()
    f_tipo = (request.args.get("tipo") or "").strip().lower()


    # força representante para não-admin
    if session.get("user") and not session.get("admin"):
        f_rep = session.get("representante", "").strip()

    # listas -> mapa id->nome
    lists = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={})
    id_to_list = {l["id"]: l.get("name", "") for l in lists}

    # busca cards
    cards = cached_trello_get(
        f"/boards/{BOARD_ID}/cards",
        params={
            "fields": "name,desc,idList,dateLastActivity,shortUrl,id",
            "attachments": "false",
            "members": "false",
        },
    )

    items: list[dict] = []
    for c in cards:
        titulo = (c.get("name") or "").strip()
        desc = c.get("desc") or ""
        lista_id = c.get("idList") or ""
        lista = id_to_list.get(lista_id, "")
        status = LIST_STATUS_MAP.get(lista, "Em aberto")
        url = c.get("shortUrl")
        dt_raw = c.get("dateLastActivity")
        

        # campos derivados
        rep      = _parse_rep_from_desc(desc)
        whats    = _parse_whatsapp_from_desc(desc)
        cliente  = _parse_cliente_from_desc(desc)   # <- seu extrator de Cliente
        sistema    = _parse_sistema_from_desc(desc)
        modulo     = _parse_modulo_from_desc(desc)
        ocorrencia = _parse_ocorrencia_from_desc(desc)
        tipo_bruto = _parse_tipo_from_desc(desc)
        tipo       = _normalize_tipo(tipo_bruto)

        # filtros simples
        if f_rep and rep != f_rep:
            continue
        if f_stat and status != f_stat:
            continue
        if f_sistema and _norm(f_sistema) != _norm(sistema):
            continue
        if f_modulo and _norm(f_modulo) != _norm(modulo):
            continue
        if f_ocor and _norm(f_ocor) != _norm(ocorrencia):
            continue
        if f_tipo and _normalize_tipo(f_tipo) != tipo:
            continue


        # filtro por última atividade (de/ate)
        if (f_de or f_ate) and dt_raw:
            try:
                d = datetime.fromisoformat(dt_raw.replace("Z", "+00:00")).date()
                if f_de and d < f_de:
                    continue
                if f_ate and d > f_ate:
                    continue
            except Exception:
                pass

        # busca textual livre
        if f_q:
            base = (titulo + "\n" + desc).lower()
            if f_q not in base:
                continue

        # filtro de Cliente — agora só pelo campo Cliente extraído
        if f_cliente:
            if f_cliente not in (cliente or "").lower():
                continue

        # inferir criação e filtrar por criação (aplica somente se AMBAS as datas vierem)
        card_id = c.get("id")
        created_at = _infer_created_from_trello_id(card_id)
        if f_de_criacao and f_ate_criacao:
            try:
                created_date = (
                    datetime.fromisoformat(created_at.replace("Z", "+00:00")).date()
                    if created_at else None
                )
            except Exception:
                created_date = None
            if created_date:
                if created_date < f_de_criacao:
                    continue
                if created_date > f_ate_criacao:
                    continue

        items.append({
            "id": card_id,
            "titulo": titulo,
            "descricao": desc,
            "cliente": cliente,
            "representante": rep,
            "lista": lista,
            "status": status,
            "url": url,
            "ultima_atividade": dt_raw,
            "whatsapp": whats,
            "created_at": created_at,
            "tipo": tipo or None,
        })

    # gerar arquivo
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "id","titulo","descricao","cliente","representante","lista",
            "status","url","ultima_atividade","whatsapp","created_at", "tipo",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for it in items:
            writer.writerow(it)
        bom = "\ufeff"
        csv_data = bom + output.getvalue()
        output.close()
        fname = f"chamados_{now_str}.csv"
        return Response(
            csv_data,
            headers={
                "Content-Disposition": f"attachment; filename={fname}",
                "Content-Type": "text/csv; charset=utf-8",
            },
        )

    elif fmt in ("xlsx", "xls"):
        df = pd.DataFrame(items)
        output = io.BytesIO()
        try:
            with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                df.to_excel(writer, index=False, sheet_name="Chamados")
        except Exception as e:
            return jsonify(success=False, message="Falha ao gerar Excel", detail=str(e)), 500
        excel_data = output.getvalue()
        output.close()
        fname = f"chamados_{now_str}.xlsx"
        return Response(
            excel_data,
            headers={
                "Content-Disposition": f"attachment; filename={fname}",
                "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            },
        )

    else:
        return jsonify(success=False, message="Formato inválido", allowed=["csv", "xlsx"]), 400




@app.route("/api/representantes")
def api_representantes():
    """
    Endpoint público para retornar a lista de representantes cadastrados.
    Retorna um array de strings com os nomes em ordem alfabética. Isso
    permite que o front-end preencha selects dinamicamente sem manter
    listas duplicadas no JavaScript.
    """
    reps = Representative.query.order_by(Representative.nome.asc()).all()
    response = jsonify([r.nome for r in reps])
    # não cachear (pra sempre vir atualizado)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



# ---------------------------------------------------------------------------
# Endpoint to fetch newly created Trello cards since a given timestamp.
#
# This endpoint accepts a `since` query parameter (ISO8601 string) and returns
# a JSON array of cards that were created after this timestamp.  The creation
# time is inferred from the card's ID (MongoDB ObjectId format).  Only cards
# belonging to the configured list (LIST_NAME / TRELLO_LIST_ID) are returned.
# It is intended to be polled periodically by the front‑end to detect new
# cards in near real time.
@app.route("/api/trello/new-cards")
def api_trello_new_cards():
    """
    Returns newly created cards on the Trello board/list since a given time.
    Expects a 'since' query parameter in ISO 8601 format (e.g. 2024-08-01T12:34:56Z).
    The response is a list of cards with fields similar to /api/chamados.
    """
    if not API_KEY or not TOKEN or not BOARD_ID:
        return (
            jsonify(
                {
                    "error": "Configuração do Trello incompleta. "
                    "Verifique TRELLO_KEY, TRELLO_TOKEN e TRELLO_BOARD.",
                    "items": [],
                }
            ),
            500,
        )

    since_raw = request.args.get("since", "")
    since_dt = None
    if since_raw:
        try:
            # Normaliza timezone: Trello usa UTC com 'Z'
            # datetime.fromisoformat não aceita 'Z', converte para '+00:00'
            s = since_raw.replace("Z", "+00:00")
            since_dt = datetime.fromisoformat(s)
        except Exception:
            since_dt = None

    # Se 'since' ausente ou inválido, retorna lista vazia
    if not since_dt:
        return jsonify([])  # nada a fazer

    try:
        # Buscar lista de cartões do board com TTL reduzido para captar rapidamente
        cards = cached_trello_get(
            f"/boards/{BOARD_ID}/cards",
            params={
                "fields": "name,desc,idList,dateLastActivity,shortUrl,id",
                "attachments": "false",
                "members": "false",
            },
            ttl=5,  # cache curto para detectar novos cartões
        )

        # Mapeia listas apenas uma vez
        lists = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={}, ttl=60)
        id_to_list = {l.get("id"): l.get("name", "") for l in lists}
        target_list_id = get_list_id()

        new_cards = []
        for c in cards:
            # Filtra somente a lista configurada se definida
            if target_list_id and c.get("idList") != target_list_id:
                continue
            cid = c.get("id")
            created_str = _infer_created_from_trello_id(cid)
            if not created_str:
                continue
            try:
                created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except Exception:
                continue
            # Only cards after 'since'
            if created_dt <= since_dt:
                continue

            list_name = id_to_list.get(c.get("idList"), "")
            status = LIST_STATUS_MAP.get(list_name, "Em aberto")
            # Extrair informações do cliente, representante e sistema da descrição
            desc = c.get("desc") or ""
            cliente = _parse_cliente_from_desc(desc)
            representante = _parse_rep_from_desc(desc)
            sistema = _parse_sistema_from_desc(desc)
            
            new_cards.append(
                {
                    "id": cid,
                    "titulo": (c.get("name") or "").strip(),
                    "descricao": desc,
                    "cliente": cliente,
                    "representante": representante,
                    "sistema": sistema,
                    "lista": list_name,
                    "status": status,
                    "url": c.get("shortUrl"),
                    "ultima_atividade": c.get("dateLastActivity"),
                    "created_at": created_str,
                }
            )

        # Ordena por criação em ordem decrescente (mais recentes primeiro)
        new_cards.sort(key=lambda x: x.get("created_at"), reverse=True)
        # A resposta é um array simples (sem metadata) para facilitar o front‑end
        return jsonify(new_cards)

    except Exception as e:
        # Oculta tokens/chaves na mensagem
        err_msg = _mask_secrets(str(e))
        return (
            jsonify(
                {
                    "error": "Erro ao consultar o Trello: " + err_msg,
                    "items": [],
                }
            ),
            500,
        )


# -----------------------------------------------------------------------------
# Login / Logout (USUÁRIO)
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().upper()
        password = (request.form.get("password") or "").strip()

        # busca sempre em MAIÚSCULO
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session["user"] = username
            session["representante"] = user.representative.nome if user.representative else ""
            session["fresh_cadastro"] = True
            if app.debug:
                print(f"[AUTH] login OK: {username}")
            return redirect(url_for("index"))
        else:
            error = "Usuário ou senha inválidos."

    return render_template("login.html", error=error)



@app.route("/logout")
def logout():
    if app.debug:
        print("[AUTH] logout")
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# Salvar chamado (formulário)
# -----------------------------------------------------------------------------
@csrf.exempt
@app.route("/salvar", methods=["POST"])
def salvar():
    data = request.form if request.form else (request.json or {})
    nome = (data.get("nome") or "").strip()
    whatsapp = (data.get("whatsapp") or "").strip()
    representante = (
        (session.get("representante") or data.get("representante") or "")
    ).strip()
    suporte = (data.get("suporte") or "").strip()
    sistema = (data.get("sistema") or "").strip()
    modulo = (data.get("modulo") or "").strip()
    ocorrencia = (data.get("ocorrencia") or "").strip()
    descricao = (data.get("descricao") or "").strip()
    observacao = (data.get("observacao") or "").strip()
    prioridade = (data.get("prioridade") or "").strip()

    # ---- Melhor mensagem de erro: listar faltantes
    labels = {
        "nome": "Nome",
        "whatsapp": "Whatsapp",
        "representante": "Representante",
        "suporte": "Suporte",
        "sistema": "Sistema",
        "modulo": "Módulo",
        "ocorrencia": "Ocorrência",
        "prioridade": "Prioridade",
    }
    faltando = [
        labels[k]
        for k, v in {
            "nome": nome,
            "whatsapp": whatsapp,
            "representante": representante,
            "suporte": suporte,
            "sistema": sistema,
            "modulo": modulo,
            "ocorrencia": ocorrencia,
            "prioridade": prioridade,
        }.items()
        if not v
    ]

    if faltando:
        msg = "Campos obrigatórios faltando: " + ", ".join(faltando) + "."
        return jsonify(success=False, message=msg), 400

    # ---- Validação de WhatsApp: exigir dígitos suficientes
    digits = re.sub(r"\D+", "", whatsapp)
    if len(digits) < 10:
        return (
            jsonify(
                success=False, message="Informe um telefone válido no campo Whatsapp."
            ),
            400,
        )

    titulo = f"{nome} - {sistema} ({ocorrencia})"
    
    tipo = (data.get("tipo") or data.get("tipoChamado") or "").strip()

    desc = (
        f"**Cliente:** {nome}\n"
        f"**Whatsapp:** {whatsapp}\n"
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

    lid = get_list_id()
    if not lid:
        return (
            jsonify(
                success=False,
                message="LIST_ID não configurado. Ajuste TRELLO_LIST/TRELLO_LIST_ID.",
            ),
            500,
        )

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
                trello_attach_file(
                    card_id, secure_filename(f.filename), f.stream, f.mimetype
                )

        trello_clear_cover(card_id)
        return jsonify(success=True, message="Chamado criado com sucesso no Trello!")
    except Exception as e:
        # Erros de rede ou da API do Trello são capturados e exibidos de forma amigável.
        err_msg = _mask_secrets(str(e))
        return (
            jsonify(success=False, message=f"Falha ao criar o chamado: {err_msg}"),
            400,
        )


# -----------------------------------------------------------------------------
# Admin (rotas) – agora usando console.html como tela principal
# -----------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html", error=None)
    u = (request.form.get("username", "") or "").strip().upper()
    p = (request.form.get("password", "") or "").strip()
    if ADMIN_USER and ADMIN_PASS and u == (ADMIN_USER or "").upper() and p == (ADMIN_PASS or ""):
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
    if not session.get("admin") or not session.pop("fresh_admin", None):
        return redirect(url_for("admin_login"))
    if not admin_logged():
        return redirect(url_for("admin_login"))
    reps = Representative.query.order_by(Representative.nome.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    # Agora o admin usa o layout do console.html
    resp = make_response(render_template("console.html", reps=reps, users=users))
    return _no_store(resp)


@app.route("/admin/rep/new", methods=["POST"])
def admin_rep_new():
    if not admin_logged():
        return redirect(url_for("admin_login"))
    # Accept either 'nome' or 'name' from the form to create a new representative.
    name = (request.form.get("nome") or request.form.get("name") or "").strip()
    created = False
    # Only create if it doesn't exist yet
    if name and not Representative.query.filter_by(nome=name).first():
        db.session.add(Representative(nome=name))
        db.session.commit()
        created = True
    if wants_json():
        reps = [
            serialize_rep(r)
            for r in Representative.query.order_by(Representative.nome.asc()).all()
        ]
        return jsonify(ok=True, created=created, reps=reps)
    # Reset fresh_admin so that after adding a representative the admin page can be reopened
    session["fresh_admin"] = True
    return redirect(url_for("admin_home"))


@app.route("/admin/rep/<int:rep_id>/delete", methods=["POST"])
def admin_rep_del(rep_id):
    if not admin_logged():
        return jsonify(ok=False, deleted=False, message="Sessão expirada, faça login novamente."), 401

    rep = Representative.query.get_or_404(rep_id)

    # Confirmação obrigatória vinda do front-end
    confirm = request.form.get("confirm") or (request.json or {}).get("confirm")
    if str(confirm).lower() not in ("1", "true", "sim", "yes"):
        msg = "Ao deletar um representante, todos os usuários vinculados também serão deletados. Confirme para prosseguir."
        return jsonify(ok=False, deleted=False, message=msg), 400

    # Deletar representante e todos os usuários vinculados
    db.session.delete(rep)
    db.session.commit()

    reps = [serialize_rep(r) for r in Representative.query.order_by(Representative.nome.asc()).all()]
    users = [serialize_user(u) for u in User.query.order_by(User.username.asc()).all()]

    return jsonify(
        ok=True,
        deleted=True,
        reps=reps,
        users=users,
        message="Representante e todos os usuários vinculados foram removidos com sucesso."
    )





@app.route("/admin/user/new", methods=["POST"])
def admin_user_new():
    if not admin_logged():
        # se não estiver logado, retorna erro em JSON
        return jsonify(ok=False, created=False, message="Sessão expirada, faça login novamente."), 401

    username = (request.form.get("username") or "").strip().upper()
    password = (request.form.get("password") or "").strip()

    # >>> FORÇAR MAIÚSCULAS <<<
    username = username.upper()

    # Aceita tanto 'representative_id' quanto 'representante_id' (compatibilidade)
    rep_id = request.form.get("representative_id") or request.form.get("representante_id")
    created = False

    if username and password and rep_id:
        rep = Representative.query.get(int(rep_id))
        exists = User.query.filter_by(username=username).first()
        if rep and not exists:
            u = User(username=username, representative=rep)
            u.set_password(password)  # grava hash + senha crua
            db.session.add(u)
            db.session.commit()
            created = True

    # Sempre responde JSON (console.html usa fetch)
    users = [serialize_user(u) for u in User.query.order_by(User.username.asc()).all()]
    return jsonify(ok=True, created=created, users=users)



@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
def admin_user_del(user_id):
    if not admin_logged():
        return jsonify(ok=False, deleted=False, message="Sessão expirada, faça login novamente."), 401

    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()

    users = [
        serialize_user(u) for u in User.query.order_by(User.username.asc()).all()
    ]
    return jsonify(
        ok=True,
        deleted=True,
        users=users,
        message="Usuário removido com sucesso."
    )



# -----------------------------------------------------------------------------
# Proxy para arquivos do Trello (resolve problemas de CORS)
# -----------------------------------------------------------------------------
@app.route("/proxy/trello-file")
def proxy_trello_file():
    """Proxy para servir arquivos do Trello, resolvendo problemas de CORS."""
    file_url = request.args.get('url')
    if not file_url:
        return jsonify({"error": "URL do arquivo não fornecida"}), 400
    
    # Verificar se é uma URL válida do Trello
    if not file_url.startswith('https://trello-attachments.s3.amazonaws.com/'):
        return jsonify({"error": "URL não autorizada"}), 403
    
    try:
        # Fazer requisição para o arquivo
        response = requests.get(file_url, stream=True, timeout=30)
        response.raise_for_status()
        
        # Determinar o tipo de conteúdo
        content_type = response.headers.get('Content-Type', 'application/octet-stream')
        
        # Criar resposta com headers apropriados
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk
        
        flask_response = Response(generate(), content_type=content_type)
        
        # Headers para permitir visualização inline
        flask_response.headers['Access-Control-Allow-Origin'] = '*'
        flask_response.headers['Access-Control-Allow-Methods'] = 'GET'
        flask_response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        
        # Para PDFs, forçar visualização inline
        if content_type == 'application/pdf':
            flask_response.headers['Content-Disposition'] = 'inline'
        
        return flask_response
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Erro ao buscar arquivo: {str(e)}"}), 500

# -----------------------------------------------------------------------------
# Compat / antigo /console -> agora redireciona para /admin
# -----------------------------------------------------------------------------
@app.route("/console")
def console_redirect():
    return redirect(url_for("admin_home"))


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify(status="ok")

@app.route("/ready")
def ready():
    """Verifica dependências principais: DB e Trello (chamada simples)."""
    checks = {"db": False, "trello": False}
    # DB: tenta simples consulta a Representatives limit 1
    try:
        _ = Representative.query.limit(1).all()
        checks["db"] = True
    except Exception as e:
        checks["db_error"] = _mask_secrets(str(e))
    # Trello: tenta listar listas (usa cache helper)
    try:
        _ = cached_trello_get(f"/boards/{BOARD_ID}/lists", params={}, ttl=5)
        checks["trello"] = True
    except Exception as e:
        checks["trello_error"] = _mask_secrets(str(e))
    http = 200 if all(checks.get(k) for k in ("db", "trello")) else 503
    return jsonify(checks), http
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    # Ative debug=True em dev para ver os logs condicionais
    app.run(host="0.0.0.0", port=port, debug=True)
