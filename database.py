import psycopg2
import os
from dotenv import load_dotenv
from psycopg2.extras import DictCursor
from contextlib import contextmanager

load_dotenv()

@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "api_auth1"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "kokin123"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", 5432)
        )
        yield conn
    finally:
        if conn:
            conn.close()

def init_db():
    
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY, 
                    email TEXT UNIQUE NOT NULL,
                    doc_number TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    username TEXT NOT NULL,
                    fullname TEXT, 
                    loggedin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    last_failed_login TIMESTAMP DEFAULT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id SERIAL PRIMARY KEY, 
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token Text NOT NULL UNIQUE,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP         
                )
            ''')
        conn.commit()

def fetch_one(query, params):
    row = None

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
    return row

def execute_query(query, params):
    last_id = None

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params)

            if 'RETURNING' in query:
                last_id_row = cursor.fetchone()
                if last_id_row:
                    last_id = last_id_row[0]

        conn.commit()
    return last_id


if __name__ == "__main__":
    print("Iniciando o banco de dados...")
    print("Criando a tabela 'users' se ela não existir...")
    init_db()
    print("Tabela 'users' verificada/criada com sucesso.")