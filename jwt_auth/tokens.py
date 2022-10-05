import datetime
import uuid

import jwt
from django.contrib.auth import settings


class Token:
    @staticmethod
    def encode_token(payload, expiration, issuer):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + expiration

        payload.update({
            'exp': int(dt.timestamp()),
            'iat': int(now.timestamp()),
            'jti': uuid.uuid4().hex,
            'iss': issuer
        })

        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    @staticmethod
    def decode_token(token, issuer):
        return jwt.decode(token, settings.SECRET_KEY, algorithms='HS256', issuer=issuer,
                          options={'require': ['uid', 'iss', 'exp', 'iat', 'jti', 'iss']})


class AccessToken(Token):
    expire_time = datetime.timedelta(minutes=15)
    issuer = 'acc'

    @staticmethod
    def encode(payload):
        return Token.encode_token(payload, expiration=AccessToken.expire_time, issuer=AccessToken.issuer)

    @staticmethod
    def decode(token):
        return Token.decode_token(token, issuer=AccessToken.issuer)


class RefreshToken:
    expire_time = datetime.timedelta(days=30)
    issuer = 'ref'

    @staticmethod
    def encode(payload):
        return Token.encode_token(payload, expiration=RefreshToken.expire_time, issuer=RefreshToken.issuer)

    @staticmethod
    def decode(token):
        return Token.decode_token(token, issuer=RefreshToken.issuer)
