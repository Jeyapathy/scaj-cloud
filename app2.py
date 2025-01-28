from flask import Flask, render_template_string, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import sqlite3
import os
from datetime import datetime, timezone
import numpy as np

from app import HTML_TEMPLATE  # Add this import for matrix operations

# Initialize Flask app
app = Flask(__name__)

# Delete existing database to update schema
if os.path.exists("secure_rsa.db"):
    os.remove("secure_rsa.db")

# Database initialization
def init_db():
    conn = sqlite3.connect("secure_rsa.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_login TEXT
        )
    """)
    conn.commit()
    conn.close()

# Generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key_pem, public_key_pem

# Compute inverse of a random square matrix
def generate_inverse_matrix(size=3):
    matrix = np.random.randint(1, 10, size=(size, size))
    try:
        inverse_matrix = np.linalg.inv(matrix)
    except np.linalg.LinAlgError:
        inverse_matrix = None  # Handle singular matrix (not invertible)
    return matrix, inverse_matrix

# Encrypt message
def encrypt_message(public_key_pem, message):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message).decode('utf-8')

# Decrypt message
def decrypt_message(private_key_pem, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    return decrypted_message

# Store encrypted message
def store_encrypted_message(encrypted_message, user_login):
    conn = sqlite3.connect("secure_rsa.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (encrypted_message, user_login, timestamp) VALUES (?, ?, ?)",
        (encrypted_message, user_login, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

# Main route
@app.route("/", methods=["GET", "POST"])
def index():
    output = None
    current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    current_user = "SCAJ"
    
    if request.method == "POST":
        original_message = request.form["message"]
        private_key_pem, public_key_pem = generate_keys()
        encrypted_message = encrypt_message(public_key_pem, original_message)
        decrypted_message = decrypt_message(private_key_pem, encrypted_message)
        
        store_encrypted_message(encrypted_message, current_user)
        
        # Generate a matrix and its inverse
        matrix, inverse_matrix = generate_inverse_matrix()

        output = {
            "original_message": original_message,
            "encrypted_message": encrypted_message,
            "decrypted_message": decrypted_message,
            "public_key": public_key_pem,
            "private_key": private_key_pem,
            "matrix": matrix.tolist(),
            "inverse_matrix": inverse_matrix.tolist() if inverse_matrix is not None else "Matrix is not invertible"
        }

    return render_template_string(HTML_TEMPLATE, 
                                output=output, 
                                current_time=current_time,
                                current_user=current_user)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)