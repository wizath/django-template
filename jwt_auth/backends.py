from django.core.exceptions import ObjectDoesNotExist
from rest_framework import authentication, exceptions

from jwt_auth.models import User
from jwt_auth.tokens import AccessToken


def authenticate_credentials(token):
    try:
        payload = AccessToken.decode(token)
    except:
        raise exceptions.AuthenticationFailed('Invalid token')

    try:
        user = User.objects.get(pk=payload.get('uid', 0))
    except ObjectDoesNotExist:
        raise exceptions.AuthenticationFailed('Wrong user credentials')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('User is not active')

    return user, token


class JWTAuthentication(authentication.BaseAuthentication):
    auth_header_prefix = 'Token'

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()
        auth_header_prefix = self.auth_header_prefix.lower()

        # Wrong header specs (empty, wrong components)
        if not auth_header or len(auth_header) == 1 or len(auth_header) > 2:
            return None

        prefix = auth_header[0].decode('utf-8')
        token = auth_header[1].decode('utf-8')

        # check for 'Authorization: Token' prefix
        if prefix.lower() != auth_header_prefix:
            return None

        return authenticate_credentials(token)


class JWTCookieAuthentication(authentication.BaseAuthentication):
    auth_cookie_prefix = 'access_token'

    def authenticate(self, request):
        raw_token = request.COOKIES.get(self.auth_cookie_prefix, None)

        if raw_token is None:
            return None

        return authenticate_credentials(raw_token)
