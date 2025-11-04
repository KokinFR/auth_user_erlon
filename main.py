from fastapi import FastAPI, Depends
from fastapi import Request
from datetime import datetime, timedelta 
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database import fetch_one, execute_query
from models import User, PasswordResetResq, Login, PasswordConfirm
from auth_utils import generate_token
from middleware import AuthMiddleware
from fastapi import HTTPException
import psycopg2
import secrets
import redis.asyncio as redis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

app = FastAPI(
    title="Auth API",
    version="1.0.0",
)

@app.on_event("startup")
async def startup():
    """
    Inicializando o redis
    """
    try:
        redis_connect = redis.from_url("redis://localhost:6379", encoding="utf-8", decode_responses=True)
        await FastAPILimiter.init(redis_connect)
        print("FastApiLIMITE conectado com redis com sucesso")
    except Exception as e:
        print(f"ERRO: Não foi possível conectar ao Redis para o Rate Limiter: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AuthMiddleware)

@app.post("/api/v1/auth/signup", dependencies=[Depends(RateLimiter(times=20, hours=1))])
async def signup(user: User):
    """
    RF01
    """
    query =  "SELECT * FROM users WHERE email = %s OR doc_number = %s"
    existing_user = fetch_one(query, (user.email, user.doc_number))
    if existing_user:
        return JSONResponse(
            status_code=400,
            content={"error": "Usuário com este email ou número de documento já existe."}
        )
    insert_query = """
    INSERT INTO users (email, doc_number, password, username, fullname, loggedin) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
    """

    try:
        user_id = execute_query(insert_query, (
            user.email,
            user.doc_number,
            user.password,
            user.username,
            user.fullname,
            True
        ))
    except psycopg2.Error as e:
        print(f"Error no Signup: {e}")
        raise HTTPException(status_code=500, detail="Erro ao criar usuário no banco de dados.")
    token = generate_token(user.email, user.doc_number)
    return {"token": token, "user_id": user_id}

@app.post("/api/v1/auth/login", dependencies=[Depends(RateLimiter(times=10, minutes=5))])
async def login(user: Login):
    """
    RF02
    """

    query = "SELECT * FROM users WHERE email = %s"
    existing_user = fetch_one(query, (user.login,))
    if not existing_user:
        return HTTPException(
            status_code=401,
            detail="Email ou senha incorreto."
        )
    failed_attempts = existing_user['failed_login_attempts']
    last_failed = existing_user['last_failed_login']

    if failed_attempts >= 3 and last_failed is not None:
        block_duration = timedelta(minutes=10)
        time_passed = datetime.now() - last_failed

        if time_passed < block_duration:
            remaining_time = (block_duration - time_passed).seconds
            remaining_minutes = (remaining_time + 59) // 60

            return HTTPException(
                status_code=403,
                detail=f"Muitas tentativas falhas. Tente novamente em {remaining_minutes} minuto(s)."
            )
    
    if existing_user["password"] != user.password:
        new_attempts = failed_attempts + 1
        fail_query = "UPDATE users SET failed_login_attempts = %s, last_failed_login = %s WHERE id = %s"
        execute_query(fail_query, (new_attempts, datetime.now(), existing_user['id']))
        return HTTPException(
            status_code=401,
            detail="Senha incorreta."
        )
    
    success_query = "UPDATE users SET loggedin = %s, failed_login_attempts = 0, last_failed_login = NULL WHERE id = %s"
    
    execute_query(success_query, (True, existing_user['id']))
    token = generate_token(existing_user['email'], existing_user['doc_number'])
    return {"token": token, "user_id": existing_user['id']}

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    """
    RF04
    """

    user = request.state.user
    query = "UPDATE users SET loggedin = %s WHERE id = %s"
    execute_query(query, (False, user["id"]))

    return JSONResponse(
        status_code=200,
        content={"message": "Logout realizado com sucesso."}
    )

@app.post("/api/v1/auth/recuperar-senha")
async def recuperar_senha(request_data: PasswordResetResq):
    """
    RF03 - Solicitar a redifinição da senha.
    """
    query = "SELECT * FROM users WHERE email = %s OR doc_number = %s"
    user = fetch_one(query, (request_data.email, request_data.document))

    success_message = {"message": "Se este e-mail estiver cadastrado, instruções de recuperação serão enviadas."}

    if user:
        token_user = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(minutes=30)

        insert_token = """INSERT INTO password_reset_tokens (user_id, token, expires_at, used) VALUES (%s, %s, %s, %s)"""

        try:
            execute_query("UPDATE password_reset_tokens SET used = TRUE WHERE user_id = %s", (user['id'],))
            execute_query(insert_token, (user['id'], token_user, expires_at, False))
        except Exception as e:
            print(f"Erro ao salvar token de reset: {e}")
            raise HTTPException(status_code=500, detail="Erro ao processar solicitação.")
        
        #await send_password_reset_email_simulation(user['email'], token_para_usuario)

    return success_message


@app.post("/api/v1/auth/recuperar-senha-conf", dependencies=[Depends(RateLimiter(times=10, minutes=15))])
async def recuperar_senha_confir(confirm_date: PasswordConfirm):
    """
    RF03 - Confirmar a recuperação de senha
    """

    token_query = """SELECT * FROM password_reset_tokens WHERE token = %s AND used = FALSE AND expires_at > %s"""

    token_data = fetch_one(token_query, (confirm_date.token, datetime.now()))

    if not token_data:
        raise HTTPException(status_code=400, detail="Token invalido.")
    
    used_id = token_data['user_id']
    new_password = confirm_date.new_password
     
    update_query = "UPDATE users SET password = %s, failed_login_attempts = 0, last_failed_login = NULL WHERE id = %s"
    execute_query(update_query, (new_password, used_id))

    invalidate_token_query = "UPDATE password_reset_tokens SET used = TRUE WHERE id = %s"
    execute_query(invalidate_token_query, (token_data['id'],))

    return {"message": "Senha atualizada com sucesso."}


@app.get("/api/v1/auth/me", dependencies=[Depends(RateLimiter(times=15, minutes=1))])
async def get_me(request: Request):
    """
    RF05
    """
    user = request.state.user

    return {
        "id": user["id"],
        "email": user["email"],
        "doc_number": user["doc_number"],
        "username": user["username"],
        "fullname": user["fullname"],
        "loggedin": user["loggedin"],
        "created_at": user["created_at"],
        "updated_at": user["updated_at"]
    }
