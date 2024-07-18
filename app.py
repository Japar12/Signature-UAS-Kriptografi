from flask import Flask, request, jsonify
import hmac
import hashlib
import base64
import json
import sqlite3

app = Flask(__name__)

def create_signature(url, datetime, body_json, secret_key):
    data_to_sign = f"{url}{datetime}{json.dumps(body_json)}"
    signature = hmac.new(secret_key.encode(), data_to_sign.encode(), hashlib.sha256).digest()
    signature_base64 = base64.b64encode(signature).decode()
    return signature_base64

def save_to_database(url, datetime, body_json, signature):
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            datetime TEXT,
            body_json TEXT,
            signature TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO signatures (url, datetime, body_json, signature)
        VALUES (?, ?, ?, ?)
    ''', (url, datetime, json.dumps(body_json), signature))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the Signature Verification System!"

@app.route('/create_signature', methods=['POST'])
def create_signature_endpoint():
    data = request.json
    if not data or 'url' not in data or 'datetime' not in data or 'body_json' not in data or 'secret_key' not in data:
        return jsonify({"error": "Invalid request. Ensure 'url', 'datetime', 'body_json', and 'secret_key' are provided in JSON format."}), 400
    
    url = data['url']
    datetime = data['datetime']
    body_json = data['body_json']
    secret_key = data['secret_key']
    
    signature = create_signature(url, datetime, body_json, secret_key)
    save_to_database(url, datetime, body_json, signature)
    return jsonify({"signature": signature})

@app.route('/verify_signature', methods=['POST'])
def verify_signature_endpoint():
    data = request.json
    if not data or 'url' not in data or 'datetime' not in data or 'body_json' not in data or 'provided_signature' not in data or 'secret_key' not in data:
        return jsonify({"error": "Invalid request. Ensure 'url', 'datetime', 'body_json', 'provided_signature', and 'secret_key' are provided in JSON format."}), 400
    
    url = data['url']
    datetime = data['datetime']
    body_json = data['body_json']
    provided_signature = data['provided_signature']
    secret_key = data['secret_key']
    
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
            return jsonify({"message": "Signature Valid!", "url": url, "body": body_json, "time": datetime})
        else:
            return jsonify({"message": "Signature Invalid!"}), 400
    else:
        return jsonify({"message": "Signature not found in database!"}), 404

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True)
