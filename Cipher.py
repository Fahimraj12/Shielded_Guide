class Cipher:
    def __init__(self, key=3):  # Default shift key is 3
        self.key = key

    def encrypt(self, data):
        encrypted_text = "".join(chr(ord(char) + self.key) for char in data)
        return encrypted_text

    def decrypt(self, encrypted_data):
        decrypted_text = "".join(chr(ord(char) - self.key) for char in encrypted_data)
        return decrypted_text

    def get_key(self):
        return self.key

    def save_key(self, filename="key.txt"):
        with open(filename, "w") as file:
            file.write(str(self.key))

    def load_key(self, filename="key.txt"):
        with open(filename, "r") as file:
            self.key = int(file.read())

    def encrypt_file(self, file_path):
        with open(file_path, "r") as file:
            data = file.read()
        encrypted_data = self.encrypt(data)
        with open(file_path, "w") as file:
            file.write(encrypted_data)

    def decrypt_file(self, file_path):
        with open(file_path, "r") as file:
            encrypted_data = file.read()
        decrypted_data = self.decrypt(encrypted_data)
        with open(file_path, "w") as file:
            file.write(decrypted_data)

    def encrypt_multiple(self, data_list):
        return [self.encrypt(data) for data in data_list]

    def decrypt_multiple(self, encrypted_list):
        return [self.decrypt(data) for data in encrypted_list]
# Create an instance of Cipher with a key shift of 3
cipher = Cipher(key=3)

# Encrypt a message
message = "Hello, World!"
encrypted_message = cipher.encrypt(message)
print("🔒 Encrypted Message:", encrypted_message)

# Decrypt the message
decrypted_message = cipher.decrypt(encrypted_message)
print("🔓 Decrypted Message:", decrypted_message)

# Save and Load Encryption Key
cipher.save_key("encryption_key.txt")
cipher.load_key("encryption_key.txt")

# Encrypt and Decrypt multiple messages
messages = ["Python", "Security", "Shielded Guide"]
encrypted_messages = cipher.encrypt_multiple(messages)
decrypted_messages = cipher.decrypt_multiple(encrypted_messages)

print("\n📜 Encrypted Messages:", encrypted_messages)
print("📖 Decrypted Messages:", decrypted_messages)
