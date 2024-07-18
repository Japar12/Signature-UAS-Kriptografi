import hmac
import hashlib
import base64
import json
import sqlite3

def create_signature(url, datetime, body_json, secret_key):
    data_to_sign = f"{url}{datetime}{json.dumps(body_json)}"
    signature = hmac.new(secret_key.encode(), data_to_sign.encode(), hashlib.sha256).digest()
    signature_base64 = base64.b64encode(signature).decode()
    return signature_base64

def save_to_database(url, datetime, body_json, signature, user):
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            datetime TEXT,
            user TEXT,
            body_json TEXT,
            signature TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO signatures (url, datetime, user, body_json, signature)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, datetime, user, json.dumps(body_json), signature))
    conn.commit()
    conn.close()

url = "/api/v1/users/create"
datetime = "2024-06-23T10:00:00Z"
user = 'admin_99'
body_json = {
    "nama": "Abdul Japar Sidik",
    "nim": "11220175",
    "email": "abduljaparsidik84@gmail.com",
}
secret_key = "656746757647dfcffcytryu5c7645vduggbjasdhagdfhadu78567576g87"

signature = create_signature(url, datetime, body_json, secret_key)
save_to_database(url, datetime, body_json, signature, user)
print(f"Signature: {signature}")

print("========================================================================================")
