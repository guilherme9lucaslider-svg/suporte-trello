import psycopg2

def salvar_registro(id, nome):
    try:
        # Conexão com o banco de dados PostgreSQL
        conn = psycopg2.connect(
            host="52.86.225.143",
            database="suporte_trello",
            user="postgres",
            password="@PGl2013A"
        )
        cursor = conn.cursor()

        # Inserir ou atualizar registro
        cursor.execute('''
            INSERT INTO representantes (nome)
            VALUES (%s)
            ON CONFLICT (id) DO UPDATE SET nome = EXCLUDED.nome
        ''', (nome))

        # Confirmar alterações
        conn.commit()

        return "salvo com sucesso"

    except Exception as e:
        return f"Erro ao salvar: {e}"

    finally:
        if conn:
            cursor.close()
            conn.close()


# Exemplo de uso:
print(salvar_registro(1, "João"))
print(salvar_registro(2, "Maria"))
