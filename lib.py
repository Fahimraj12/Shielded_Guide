import hashlib
import secrets
import logging
import time
import re
from cryptography.fernet import Fernet


# 1. Cipher Class (AES Encryption)
class Cipher:
    def __init__(self, key=None):
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()

    def get_key(self):
        return self.key

    def save_key(self, filename="key.key"):
        with open(filename, "wb") as file:
            file.write(self.key)

    def load_key(self, filename="key.key"):
        with open(filename, "rb") as file:
            self.key = file.read()
            self.cipher = Fernet(self.key)

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as file:
            encrypted_data = self.encrypt(file.read().decode())
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

    def decrypt_file(self, file_path):
        with open(file_path, "rb") as file:
            decrypted_data = self.decrypt(file.read())
        with open(file_path, "wb") as file:
            file.write(decrypted_data.encode())

    def encrypt_multiple(self, data_list):
        return [self.encrypt(data) for data in data_list]

    def decrypt_multiple(self, encrypted_list):
        return [self.decrypt(data) for data in encrypted_list]


# 2. AuthManager Class (User Authentication)
class AuthManager:
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password, hashed):
        return self.hash_password(password) == hashed

    def generate_salt(self):
        return secrets.token_hex(8)

    def hash_with_salt(self, password, salt):
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def generate_otp(self):
        return secrets.randbelow(1000000)

    def verify_otp(self, otp, actual_otp):
        return otp == actual_otp

    def generate_token(self):
        return secrets.token_hex(32)

    def verify_token(self, token, actual_token):
        return token == actual_token

    def generate_api_key(self):
        return secrets.token_urlsafe(32)

    def validate_api_key(self, key, valid_keys):
        return key in valid_keys


# 3. AccessControl Class (Role-Based Access Control)
class AccessControl:
    def __init__(self):
        self.roles = {}

    def add_role(self, user, role):
        self.roles[user] = role

    def remove_role(self, user):
        if user in self.roles:
            del self.roles[user]

    def check_access(self, user, required_role):
        return self.roles.get(user) == required_role

    def list_roles(self):
        return self.roles

    def has_role(self, user):
        return user in self.roles

    def update_role(self, user, new_role):
        if user in self.roles:
            self.roles[user] = new_role

    def grant_admin(self, user):
        self.roles[user] = "admin"

    def revoke_admin(self, user):
        if self.roles.get(user) == "admin":
            self.roles[user] = "user"

    def clear_roles(self):
        self.roles.clear()


# 4. SecureLogger Class (Secure Logging)
class SecureLogger:
    def __init__(self, log_file="security.log"):
        self.logger = logging.getLogger("ShieldedGuide")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        self.logger.addHandler(handler)

    def log(self, message):
        self.logger.info(message)

    def log_warning(self, message):
        self.logger.warning(message)

    def log_error(self, message):
        self.logger.error(message)

    def log_critical(self, message):
        self.logger.critical(message)

    def log_access(self, user, action):
        self.logger.info(f"{user} performed {action}")

    def log_failed_attempt(self, user):
        self.logger.warning(f"Failed attempt by {user}")

    def log_successful_login(self, user):
        self.logger.info(f"{user} logged in successfully")

    def log_admin_action(self, admin, action):
        self.logger.info(f"Admin {admin} executed {action}")

    def log_encryption_action(self, action):
        self.logger.info(f"Encryption action: {action}")

    def log_security_breach(self, user):
        self.logger.critical(f"Security breach detected for user {user}")


# 5. DataSanitizer Class (Security Protection)
class DataSanitizer:
    def sanitize_sql(self, input_string):
        return input_string.replace("'", "''")  

    def sanitize_xss(self, input_string):
        return input_string.replace("<", "&lt;").replace(">", "&gt;")

    def sanitize_url(self, url):
        return re.sub(r"[^\w:/?=&]", "", url)

    def remove_html_tags(self, input_string):
        return re.sub(r"<.*?>", "", input_string)

    def sanitize_email(self, email):
        return re.sub(r"[^\w@.]", "", email)

    def sanitize_phone_number(self, phone):
        return re.sub(r"[^\d]", "", phone)

    def sanitize_username(self, username):
        return re.sub(r"[^\w]", "", username)

    def prevent_script_injection(self, input_string):
        return re.sub(r"(<script.*?>.*?</script>)", "", input_string, flags=re.DOTALL)

    def sanitize_json(self, json_string):
        return re.sub(r"[^\w{}:,\[\]\" ]", "", json_string)

    def validate_safe_input(self, input_string):
        return bool(re.match(r"^[\w\s\.\-\@]+$", input_string))


# 6. SessionManager Class (Session Tokens)
class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user):
        token = secrets.token_hex(16)
        self.sessions[user] = token
        return token

    def verify_session(self, user, token):
        return self.sessions.get(user) == token

    def expire_session(self, user):
        if user in self.sessions:
            del self.sessions[user]

    def list_active_sessions(self):
        return self.sessions

    def get_user_by_token(self, token):
        for user, user_token in self.sessions.items():
            if user_token == token:
                return user
        return None

    def extend_session(self, user):
        if user in self.sessions:
            self.sessions[user] = secrets.token_hex(16)

    def clear_all_sessions(self):
        self.sessions.clear()

    def session_exists(self, user):
        return user in self.sessions

    def generate_timed_token(self, expiration_seconds=300):
        return f"{secrets.token_hex(16)}|{time.time() + expiration_seconds}"

    def verify_timed_token(self, token):
        token_parts = token.split("|")
        if len(token_parts) != 2:
            return False
        return float(token_parts[1]) > time.time()


# Example Usage
if __name__ == "__main__":
    cipher = Cipher()
    print("Encrypted:", cipher.encrypt("Secure Data"))
    print("Decrypted:", cipher.decrypt(cipher.encrypt("Secure Data")))
