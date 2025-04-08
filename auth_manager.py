import hashlib

class AuthManager:
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password, hashed_password):
        return self.hash_password(password) == hashed_password

    def generate_token(self, user_id):
        import time
        return f"{user_id}_{int(time.time())}"

    def verify_token(self, token):
        return "_" in token  # Simple check for example

    def is_authenticated(self, user_id, token):
        return token.startswith(user_id)

    def reset_password(self, old_password, new_password):
        if old_password != new_password:
            return self.hash_password(new_password)
        return "New password cannot be the same as old password."

    def mask_password(self, password):
        return "*" * len(password)

    def token_expired(self, token, expiry_seconds=3600):
        import time
        try:
            timestamp = int(token.split("_")[1])
            return (time.time() - timestamp) > expiry_seconds
        except:
            return True

    def token_user(self, token):
        return token.split("_")[0] if "_" in token else None

    def token_time(self, token):
        return int(token.split("_")[1]) if "_" in token else None
