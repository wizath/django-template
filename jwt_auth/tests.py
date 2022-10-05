import datetime
import uuid

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth import settings

from .tokens import Token
import jwt

User = get_user_model()


class TokenSecurityTests(TestCase):
    def test_jwt_token_no_algorithm_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'issuer': 'test'
        }, None, algorithm='none')

        with self.assertRaises(jwt.exceptions.InvalidAlgorithmError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_no_claims_exception(self):
        token = jwt.encode({
            'uid': 1
        }, settings.SECRET_KEY, algorithm='HS256')

        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_wrong_algorithm_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS512')

        with self.assertRaises(jwt.exceptions.InvalidAlgorithmError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_expired_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now - datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS256')

        with self.assertRaises(jwt.exceptions.ExpiredSignatureError):
            Token.decode_token(token, issuer='test')

    def test_jwt_wrong_token_exception(self):
        with self.assertRaises(jwt.exceptions.DecodeError):
            Token.decode_token('wrong token', issuer='test')

    def test_jwt_proper_token(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS256')

        self.assertNotEquals(Token.decode_token(token, issuer='test'), None)

# 1. No authorization header
# 2. Wrong authorization header length
# 3. No token, good header
# 4. Wrong token
# 5. No User ID
# 6. User is disabled
# 7. No cookie, no token
# 8. Wrong cookie, no token
# 9. Good Cookie, Good Token
# 10. Good token
