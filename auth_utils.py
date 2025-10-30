import base64
from database import fetch_one


def generate_token(email: str, doc_number: str) -> str:
    """
    gera um token simples em base64
    """
    data_string = f"{email}:{doc_number}"
    data_bytes = data_string.encode('utf-8')
    token =  base64.b64encode(data_bytes).decode('utf-8')
    return f"SDWork {token}"

def verify_token(token: str):
    """
    Verificar o token decodificando o base64 e buscando o usuário no banco de dados
    """

    if not token or not token.startswith("SDWork "):
        return None
    
    token = token.split(" ")[1]
    try:
        decoded_bytes = base64.b64decode(token.encode('utf-8'))
        decoded_string = decoded_bytes.decode('utf-8')
        email, doc_number = decoded_string.split(":")
    except Exception:
        return None
    
    query = "SELECT * FROM users WHERE email = %s AND doc_number = %s"
    user = fetch_one(query, (email, doc_number))
    return user