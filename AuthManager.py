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
