"""Print a PBKDF2-SHA256 hash for CYBERSHIELD_*_PASSWORD_HASH environment variables."""
import getpass, hashlib, secrets
password = getpass.getpass("Password (minimum 14 characters recommended): ")
if len(password) < 12:
    raise SystemExit("Use at least 12 characters.")
salt = secrets.token_hex(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000).hex()
print(f"pbkdf2_sha256${salt}${digest}")
