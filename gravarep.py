import os
import psycopg2
from urllib.parse import urlparse

def _get_conn():
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        # psycopg2 aceita a URL diretamente
        return psycopg2.connect(dsn)
    host = os.getenv("DB_HOST", "localhost")
    db   = os.getenv("DB_NAME", "suporte_trello")
    user = os.getenv("DB_USER", "postgres")
    pwd  = os.getenv("DB_PASS", "")
    return psycopg2.connect(host=host, database=db, user=user, password=pwd)


def salvar_registro(rep_id: int, nome: str):
    try:
        # Conexão com o banco de dados PostgreSQL
        conn = _get_conn()
        cursor = conn.cursor()

        # Inserir ou atualizar registro
        cursor.execute(
            '''
            INSERT INTO representantes (id, nome)
            VALUES (%s, %s)
            ON CONFLICT (id) DO UPDATE SET nome = EXCLUDED.nome
            ''',
            (rep_id, nome)
        )

        # Confirmar alterações
        conn.commit()

        return "salvo com sucesso"

    except Exception as e:
        return f"Erro ao salvar: {e}"

    finally:
        try:
            if cursor:
                cursor.close()
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass


# Exemplo de uso:
if __name__ == "__main__":
    print(salvar_registro(1, "João"))
    print(salvar_registro(2, "Maria"))
