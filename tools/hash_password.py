from werkzeug.security import generate_password_hash
pwd = input("Senha: ")
print(generate_password_hash(pwd))
