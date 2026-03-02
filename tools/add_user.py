import json, sys, pathlib
from werkzeug.security import generate_password_hash

BASE = pathlib.Path(__file__).resolve().parents[1]
USERS_FILE = BASE / "users.json"

def load():
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    return {}

def save(data):
    USERS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def main():
    if len(sys.argv) < 4:
        # Mensagem de uso: encapsule o nome do representante entre aspas se contiver espaços
        print("Uso: python tools/add_user.py \"NOME DO REPRESENTANTE\" username senha")
        sys.exit(1)

    representante = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    data = load()
    data.setdefault(representante, {"users": []})

    # evitar duplicado
    for u in data[representante]["users"]:
        if u["username"] == username:
            print("Já existe esse usuário nesse representante.")
            sys.exit(2)

    data[representante]["users"].append({
        "username": username,
        "password_hash": generate_password_hash(password)
    })
    save(data)
    print("Usuário adicionado com sucesso.")

if __name__ == "__main__":
    main()
