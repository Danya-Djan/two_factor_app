from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import paramiko
import io
import base64
import pyotp
import qrcode
import secrets
from time import time
from typing import Dict, Tuple

app = FastAPI()

# Add session middleware; be sure to use a proper secret key for production!
app.add_middleware(SessionMiddleware, secret_key="some_super_secret_key")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Helper functions for flash messages.
def add_flash(request: Request, message: str, category: str):
    if "flash" not in request.session:
        request.session["flash"] = []
    flash_list = request.session["flash"]
    flash_list.append({"category": category, "message": message})
    request.session["flash"] = flash_list

def pop_flash(request: Request):
    messages = request.session.get("flash", [])
    request.session["flash"] = []
    return messages

REMOTE_HOST = "10.255.255.20"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
failed_attempts: Dict[str, Tuple[int, float]] = {}

def check_rate_limit(request: Request) -> bool:
    """
    Check if the IP is currently rate limited.
    Returns True if the request should be blocked.
    """
    client_ip = request.client.host
    if client_ip in failed_attempts:
        attempts, timestamp = failed_attempts[client_ip]
        # If enough time has passed, reset the counter
        if time() - timestamp > LOCKOUT_TIME:
            failed_attempts.pop(client_ip)
            return False
        # Block if too many attempts
        if attempts >= MAX_ATTEMPTS:
            return True
    return False

def record_failed_attempt(request: Request):
    """Record a failed login attempt for the IP address."""
    client_ip = request.client.host
    current_time = time()
    if client_ip in failed_attempts:
        attempts, _ = failed_attempts[client_ip]
        failed_attempts[client_ip] = (attempts + 1, current_time)
    else:
        failed_attempts[client_ip] = (1, current_time)

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    flash_messages = pop_flash(request)
    return templates.TemplateResponse("login.html", {"request": request, "flash_messages": flash_messages})

@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if check_rate_limit(request):
        return RedirectResponse(url="/too-many-attempts", status_code=status.HTTP_303_SEE_OTHER)

    # Connect via SSH to remote server using provided credentials.
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(REMOTE_HOST, username=username, password=password)
        # If login successful, clear any failed attempts for this IP
        client_ip = request.client.host
        if client_ip in failed_attempts:
            failed_attempts.pop(client_ip)
        
        # Check if the key for this user has already been generated on the remote server.
        stdin, stdout, stderr = client.exec_command('if [ -f ~/.google_authenticator ]; then echo exists; else echo not_exists; fi')
        file_status = stdout.read().decode().strip()
        if file_status == "exists":
            add_flash(request, "Ключ для данного пользователя уже сгенерирован.", "info")
            client.close()
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        # Record the failed attempt
        record_failed_attempt(request)
        if check_rate_limit(request):
            return RedirectResponse(url="/too-many-attempts", status_code=status.HTTP_303_SEE_OTHER)
        add_flash(request, f"Ошибка подключения: {str(e)}", "error")
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # SSH connection was successful.
    # Generate a new TOTP secret locally.
    secret = pyotp.random_base32()
    # Save secret in session for later token verification.
    request.session["secret"] = secret
    # Store the username (do not store the password).
    request.session["remote_username"] = username
    
    # Configure the remote server for two‑factor authentication by writing
    # the secret into the .google_authenticator file.
    setup_command = f'echo "{secret}" > ~/.google_authenticator && chmod 600 ~/.google_authenticator'
    try:
        stdin, stdout, stderr = client.exec_command(setup_command)
        stdout.channel.recv_exit_status()  # wait for command to complete
        error = stderr.read().decode().strip()
        if error:
            add_flash(request, f"Error during remote 2FA setup: {error}", "error")
            client.close()
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        add_flash(request, f"Remote setup command failed: {str(e)}", "error")
        client.close()
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    client.close()
    # Redirect to the page where the QR code is displayed.
    return RedirectResponse(url="/setup", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/setup", response_class=HTMLResponse)
async def setup_get(request: Request):
    # Get the TOTP secret from the session.
    secret = request.session.get("secret")
    if not secret:
        add_flash(request, "No TOTP secret found. Please login again.", "error")
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    totp = pyotp.TOTP(secret)
    # Retrieve the username used during login.
    remote_username = request.session.get("remote_username", "user")
    # Create the account using the provided username and "lins.ru" as the domain.
    account = f"{remote_username}@lins.ru"
    otp_url = totp.provisioning_uri(name=account, issuer_name="LINS VPN")
    
    # Generate a QR code from the provisioning URL.
    qr = qrcode.make(otp_url)
    img_io = io.BytesIO()
    qr.save(img_io, "PNG")
    img_io.seek(0)
    encoded_img = base64.b64encode(img_io.getvalue()).decode("ascii")
    
    flash_messages = pop_flash(request)
    
    return templates.TemplateResponse("setup.html", {
        "request": request,
        "img_data": encoded_img,
        "flash_messages": flash_messages
    })

@app.post("/setup", response_class=HTMLResponse)
async def setup_post(request: Request, token: str = Form(...)):
    secret = request.session.get("secret")
    if not secret:
        add_flash(request, "Session expired. Please login again.", "error")
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    totp = pyotp.TOTP(secret)
    if totp.verify(token):
        # Generate recovery codes (e.g., 5 codes, each 8 digits long)
        recovery_codes = [f"{secrets.randbelow(10**8):08d}" for _ in range(5)]
        request.session["recovery_codes"] = recovery_codes
        add_flash(request, "Two-factor authentication is successfully set up!", "success")
        return RedirectResponse(url="/recovery", status_code=status.HTTP_303_SEE_OTHER)
    else:
        add_flash(request, "Invalid token. Please try again.", "error")
        return RedirectResponse(url="/setup", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/recovery", response_class=HTMLResponse)
async def recovery_get(request: Request):
    recovery_codes = request.session.get("recovery_codes", None)
    if not recovery_codes:
        add_flash(request, "No recovery codes found. Please complete 2FA setup.", "error")
        return RedirectResponse(url="/setup", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("recovery.html", {
        "request": request,
        "recovery_codes": recovery_codes,
        "flash_messages": pop_flash(request)
    })

@app.get("/too-many-attempts", response_class=HTMLResponse) 
async def too_many_attempts(request: Request):
    return templates.TemplateResponse("too_many_attempts.html", {
        "request": request,
        "lockout_minutes": LOCKOUT_TIME // 60,
        "flash_messages": pop_flash(request)
    })

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, debug=True) 