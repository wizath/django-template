import datetime
import uuid

import jwt
from django.contrib.auth import settings


class Token:

    @staticmethod
    def encode_token(payload, expiration, issuer):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now - expiration

        claims = payload.update({
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': issuer
        })
        token = jwt.encode(claims, settings.SECRET_KEY, algorithm='HS256')
        return token.decode('utf-8')

    @staticmethod
    def decode_token(token, issuer):
        return jwt.decode(token, settings.SECRET_KEY, algorithms='HS256', issuer=issuer,
                          options={'require': ['uid', 'iss', 'exp', 'iat', 'jti', 'iss']})


class AccessToken(Token):
    expire_time = datetime.timedelta(minutes=15)

    @staticmethod
    def encode(payload):
        Token.encode_token(payload, expiration=AccessToken.expire_time, issuer='acc')

    @staticmethod
    def decode(token):
        return Token.decode_token(token, issuer='acc')


class RefreshToken:
    expire_time = datetime.timedelta(days=30)

    @staticmethod
    def encode(payload):
        Token.encode_token(payload, expiration=RefreshToken.expire_time, issuer='ref')

    @staticmethod
    def decode(token):
        return Token.decode_token(token, issuer='ref')
