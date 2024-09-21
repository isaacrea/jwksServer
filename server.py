from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
import uuid
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Initialize Flask app
app = Flask(__name__)


# Key class to store key information
class Key:
    def __init__(self, kid, private_key, public_key, expires_at):
        self.kid = kid
        self.private_key = private_key
        self.public_key = public_key
        self.expires_at = expires_at


# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Function to encode integers using base64url
def base64url_encode(value):
    # Convert integer to bytes
    bytes_value = int_to_bytes(value)
    # Base64url encode
    encoded = base64.urlsafe_b64encode(bytes_value)
    # Return string without padding
    return encoded.decode('utf-8').rstrip('=')


# Function to convert integer to bytes
def int_to_bytes(value):
    # Calculate byte length
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, 'big')


# List to store keys
keys = []

# Generate unexpired key
current_time = datetime.now(timezone.utc)
unexpired_expires_at = current_time + timedelta(hours=1)

unexpired_private_key, unexpired_public_key = generate_rsa_key_pair()
unexpired_kid = str(uuid.uuid4())
unexpired_key = Key(
    kid=unexpired_kid,
    private_key=unexpired_private_key,
    public_key=unexpired_public_key,
    expires_at=unexpired_expires_at,
)
keys.append(unexpired_key)

# Generate expired key
expired_expires_at = current_time - timedelta(hours=1)
expired_private_key, expired_public_key = generate_rsa_key_pair()
expired_kid = str(uuid.uuid4())
expired_key = Key(
    kid=expired_kid,
    private_key=expired_private_key,
    public_key=expired_public_key,
    expires_at=expired_expires_at,
)
keys.append(expired_key)


# JWKS endpoint to serve public keys in JWKS format
@app.route('/.well-known/jwks.json')
def jwks():
    # Filter unexpired keys
    unexpired_keys = [key for key in keys if key.expires_at >
                      datetime.now(timezone.utc)]
    jwks_keys = []
    for key in unexpired_keys:
        public_numbers = key.public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        jwk = {
            'kty': 'RSA',
            'use': 'sig',
            'kid': key.kid,
            'n': base64url_encode(n),
            'e': base64url_encode(e),
        }
        jwks_keys.append(jwk)
    return jsonify({'keys': jwks_keys})


# /auth endpoint to issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    # Check if 'expired' query parameter is present
    expired = 'expired' in request.args
    if expired:
        # Use the expired key and set expired expiry
        key = expired_key
        exp = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        # Use the unexpired key and set future expiry
        key = unexpired_key
        exp = datetime.now(timezone.utc) + timedelta(minutes=30)

    # JWT payload
    payload = {
        'sub': 'user123',
        'iat': datetime.now(timezone.utc),
        'exp': exp,
    }

    # JWT headers with kid
    headers = {
        'kid': key.kid
    }

    # Serialize private key to PEM format
    private_key_pem = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Sign JWT
    token = jwt.encode(
        payload,
        private_key_pem,
        algorithm='RS256',
        headers=headers
    )

    return jsonify({'token': token})


# Run the Flask app on port 8080
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
