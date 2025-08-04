import hashlib
import hmac
import os
import base64


class HashPasswordClient:
    def __init__(self):
        self.iteration_count = 100_000
        self.salt_length = 16

    def hash_password(self, raw_password: str) -> str:
        salt = os.urandom(self.salt_length)

        password_bytes = raw_password.encode('utf-8')
        hash_bytes = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password_bytes,
            salt=salt,
            iterations=self.iteration_count,
        )

        salt_b64 = base64.b64encode(salt).decode('utf-8')
        hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')

        return f"{salt_b64}${hash_b64}"

    def validate_password(self, input_password: str, hashed_password: str) -> bool:
        salt_b64, hash_64 = hashed_password.split("$")
        salt = base64.b64decode(salt_b64)
        original_hash = base64.b64decode(hash_64)

        password_bytes = input_password.encode('utf-8')
        new_hash = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password_bytes,
            salt=salt,
            iterations=self.iteration_count
        )

        return hmac.compare_digest(original_hash, new_hash)

a = HashPasswordClient()

b = a.hash_password("Hello!")
print(a.validate_password("Hello!", b))