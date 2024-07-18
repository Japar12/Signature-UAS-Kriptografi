import hmac
import hashlib
import base64
import json
import sqlite3

url = "/api/v1/users/create"
datetime = "2024-06-23T10:00:00Z"
body_json = {
    "nama": "Abdul Japar Sidik",
    "nim": "11220175",
    "email": "abduljaparsidik84@gmail.com",
}
secret_key = "656746757647dfcffcytryu5c7645vduggbjasdhagdfhadu78567576g87"

def verify_signature(url, datetime, body_json, provided_signature, secret_key):
    data_to_sign = f"{url}{datetime}{json.dumps(body_json)}"
    expected_signature = hmac.new(secret_key.encode(), data_to_sign.encode(), hashlib.sha256).digest()
    expected_signature_base64 = base64.b64encode(expected_signature).decode()
    return hmac.compare_digest(expected_signature_base64, provided_signature)

def fetch_signature_from_db(url, datetime, body_json):
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT signature FROM signatures
        WHERE url = ? AND datetime = ? AND body_json = ?
    ''', (url, datetime, json.dumps(body_json)))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

provided_signature = fetch_signature_from_db(url, datetime, body_json)
if provided_signature:
    is_valid = verify_signature(url, datetime, body_json, provided_signature, secret_key)
    if is_valid:
        print('Signature Valid!')
        print(f"URL: {url}")
        print(f"Body: {body_json}")
        print(f"Time: {datetime}")
    else:
        print('Signature Invalid!')
else:
    print('Signature not found in database!')
