import json, pathlib
from app import app, db, Representative, User

BASE = pathlib.Path(__file__).resolve().parents[1]
USERS_FILE = BASE / "users.json"

with app.app_context():
    data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    for rep_name, obj in data.items():
        rep = Representative.query.filter_by(nome=rep_name).first()
        if not rep:
            rep = Representative(nome=rep_name)
            db.session.add(rep)
            db.session.commit()
        for item in obj.get("users", []):
            username = item["username"]
            password_hash = item["password_hash"]
            if not User.query.filter_by(username=username).first():
                u = User(username=username, representative=rep, password_hash=password_hash)
                db.session.add(u)
    db.session.commit()
    print("Importação concluída.")
