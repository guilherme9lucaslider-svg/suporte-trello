import os
from dotenv import load_dotenv
load_dotenv()

from app import app, db

def main():
    with app.app_context():
        db.create_all()
        print("Tabelas criadas (se não existiam).")

if __name__ == "__main__":
    main()


