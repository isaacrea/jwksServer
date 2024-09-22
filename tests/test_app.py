# tests/test_app.py

import pytest
from jwksServer.server import app  # Import the Flask app
import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64


@pytest.fixture
def client():
    app.testing = True
    with app.test_client() as client:
        yield client


def test_jwks_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0  # Should have at least one unexpired key


def test_auth_endpoint_unexpired(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    token = data['token']
    assert token is not None
    # Further validate the token
    validate_jwt(token, client)


def test_auth_endpoint_expired(client):
    response = client.post('/auth?expired')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    token = data['token']
    assert token is not None
    # Further validate the token
    with pytest.raises(jwt.InvalidTokenError):
        validate_jwt(token, client)


def validate_jwt(token, client):
    import jwt
    from jwt import InvalidTokenError
    unverified_headers = jwt.get_unverified_header(token)
    kid = unverified_headers['kid']

    # Fetch JWKS
    jwks_response = client.get('/.well-known/jwks.json')
    jwks = jwks_response.get_json()

    # Find the key with matching kid
    key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
    if key is None:
        raise InvalidTokenError("Public key not found in JWKS")

    # Rest of your code to construct the public key and verify the token
    # Decode 'n' and 'e' from Base64URL
    def base64url_decode(input):
        rem = len(input) % 4
        if rem > 0:
            input += '=' * (4 - rem)
        return base64.urlsafe_b64decode(input)

    n = int.from_bytes(base64url_decode(key['n']), 'big')
    e = int.from_bytes(base64url_decode(key['e']), 'big')
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()

    # Verify the token
    payload = jwt.decode(token, public_key, algorithms=['RS256'])
    assert payload['sub'] == 'user123'
