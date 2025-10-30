from fastapi import FastAPI
from fastapi import Request
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database import fetch_one, execute_query
from models import User, Token, PasswordRecovery, Login
from auth_utils import generate_token, verify_token
from middleware import AuthMiddleware
from fastapi import HTTPException
import psycopg2

app = FastAPI(
    title="Auth API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AuthMiddleware)

@app.post("/api/v1/auth/signup")
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

@app.post("/api/v1/auth/login")
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
async def recuperar_senha(recovery_data: PasswordRecovery):
    """
    RF03
    """

    query = "SELECT * FROM users WHERE email = %s AND doc_number = %s"
    db_user = fetch_one(query, (recovery_data.email, recovery_data.document))
    if not db_user:
        return HTTPException(
            status_code=404,
            detail="Usuário não encontrado."
        )
    
    new_password_ = recovery_data.new_password
    update_query = "UPDATE users SET password = %s WHERE id = %s"
    execute_query(update_query, (new_password_, db_user['id']))

    token = generate_token(recovery_data.email, recovery_data.document)
    return {"token": token, "message": "Senha atualizada com sucesso."}

@app.get("/api/v1/auth/me")
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
