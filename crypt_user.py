from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY =  os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise "Chave não encontrada, gerer uma SECRET_KEY"

try:
    cipher_suite = Fernet(SECRET_KEY.encode('utf-8'))
except Exception as e:
    raise ValueError(f"Chave secreta inválida.")

def encrypt_token(token_plaintext: str) -> str:
    """
    Criptografia do token
    """
    encrypt_bytes = cipher_suite.encrypt(token_plaintext.encode('utf-8'))
    return encrypt_bytes.decode('utf-8')

def decript_token(token_encrypt: str) -> str:
    """
    Descriptografar o token
    """
    try:
        decript_bytes = cipher_suite.decrypt(token_encrypt.encode('utf-8'))
        return decript_bytes.decode('utf-8')
    except Exception:
        return None
