import jwt
from datetime import datetime, timedelta
from jwt import ExpiredSignatureError
import json

SECRET = 'LEISDElezvz$2a$04$TiS2kzpqRd.xqJdIJ9vXlTv8sbxuarlrc/if475z'
TOKEN_KEY = 'token'
REFRESH_TOKEN_KEY = 'refresh_token'
JWT_EXPIRATION_KEY = 'exp'
DECODING_OPTIONS = {'verify_exp': False}
HASH_ALGORITHM = 'HS256'
TOKEN_STRING_ENCODING = "utf-8"


class AuthGuard:

    @staticmethod
    def decode_token(token):
        return jwt.decode(token, SECRET, algorithm=HASH_ALGORITHM, options=DECODING_OPTIONS)

    @staticmethod
    def has_token_expired(encoded_token):
        decoded_auth_token = AuthGuard.decode_token(encoded_token)
        current_time = datetime.now()
        auth_token_time = decoded_auth_token[JWT_EXPIRATION_KEY]
        expired = auth_token_time < current_time

        if expired:
            raise ExpiredSignatureError

        return decoded_auth_token

    @staticmethod
    def encode_token(payload):
        return jwt.encode(payload, SECRET, algorithm=HASH_ALGORITHM).decode(TOKEN_STRING_ENCODING)

    @staticmethod
    def auth_response(user):
        user = json.loads(user)
        expiry_time = datetime.now() + timedelta(minutes=1)
        encoded_jwt = AuthGuard.encode_token({
            'id': user.get('id'),
            JWT_EXPIRATION_KEY: expiry_time
        })
        refresh_token = AuthGuard.encode_token({
            TOKEN_KEY: encoded_jwt,
            'id': user.get('id')
        })
        response_data = {
            TOKEN_KEY: encoded_jwt,
            REFRESH_TOKEN_KEY: refresh_token,
            'User': user
        }
        return response_data

