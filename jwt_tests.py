import datetime
import uuid
import jwt
import os

now = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=1)
dt = now - datetime.timedelta(minutes=1)
secret = os.urandom(256).hex()

token = jwt.encode({
    'uid': 1,
    'exp': dt.timestamp(),
    'iat': now.timestamp(),
    'jti': uuid.uuid4().hex
}, None, algorithm='none')
print(token)

result = jwt.decode(token, secret, algorithms='HS256')
print(result)
