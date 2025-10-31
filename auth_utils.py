import base64
from database import fetch_one
from crypt_user import decript_token, encrypt_token


def generate_token(email: str, doc_number: str) -> str:
    """
    gera um token simples em cript
    """
    data_string = f"{email}:{doc_number}"
    token_data = encrypt_token(data_string)
    return f"SDWork {token_data}"

def verify_token(token: str):
    """
    Verificar o token decodificando o base64 e buscando o usuário no banco de dados
    """

    if not token or not token.startswith("SDWork "):
        return None
    
    token_decript = token.split(" ")[1]
    
    try:
        decript_strings = decript_token(token_decript)
        
        if not decript_strings:
            return None
        email, doc_number, = decript_strings.split(":") 
    except Exception:
        return None
    
    query = "SELECT * FROM users WHERE email = %s AND doc_number = %s"
    user = fetch_one(query, (email, doc_number))
    return user