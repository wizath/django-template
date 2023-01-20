from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from rest_framework import authentication, exceptions

from user.models import User
from authentication.models import UserRefreshToken
from authentication.tokens import AccessToken, RefreshToken

UserModel = get_user_model()


def get_authentication_token(prefix, request):
    auth_header = authentication.get_authorization_header(request).split()
    auth_header_prefix = prefix.lower()

    # Wrong header specs (empty, wrong components)
    if not auth_header or len(auth_header) == 1 or len(auth_header) > 2:
        return None

    prefix = auth_header[0].decode('utf-8')
    token = auth_header[1].decode('utf-8')

    # check for 'Authorization: Token' prefix
    if prefix.lower() != auth_header_prefix:
        return None

    return token


def authenticate_credentials(token, token_class=AccessToken):
    try:
        payload = token_class.decode(token)
    except:
        raise exceptions.AuthenticationFailed('Invalid token')

    try:
        user = User.objects.get(pk=payload.get('uid'))
    except ObjectDoesNotExist:
        raise exceptions.AuthenticationFailed('Wrong user credentials')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('User is not active')

    if token_class == RefreshToken:
        if UserRefreshToken.objects.filter(jti=payload.get('jti'), blacklisted=True).exists():
            raise exceptions.AuthenticationFailed('Token is blacklisted')

    return user, token


class JWTRefreshAuthentication(authentication.BaseAuthentication):
    auth_header_prefix = 'Bearer'

    def authenticate(self, request):
        token = get_authentication_token(self.auth_header_prefix, request)
        return authenticate_credentials(token, token_class=RefreshToken)  # noqa


class JWTRefreshCookieAuthentication(authentication.BaseAuthentication):
    auth_cookie_prefix = 'refresh_token'

    def authenticate(self, request):
        raw_token = request.COOKIES.get(self.auth_cookie_prefix, None)

        if raw_token is None:
            return None

        return authenticate_credentials(raw_token, token_class=RefreshToken)  # noqa


class JWTAuthentication(authentication.BaseAuthentication):
    auth_header_prefix = 'Bearer'

    def authenticate(self, request):
        token = get_authentication_token(self.auth_header_prefix, request)
        return authenticate_credentials(token)


class JWTCookieAuthentication(authentication.BaseAuthentication):
    auth_cookie_prefix = 'access_token'

    def authenticate(self, request):
        raw_token = request.COOKIES.get(self.auth_cookie_prefix, None)

        if raw_token is None:
            return None

        return authenticate_credentials(raw_token)


class DualCredentialBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = UserModel.objects.get(Q(username__iexact=username) | Q(email__iexact=username))
        except UserModel.DoesNotExist:
            UserModel().set_password(password)
            return
        except UserModel.MultipleObjectsReturned:
            user = UserModel.objects.filter(Q(username__iexact=username) | Q(email__iexact=username)).order_by(
                'id').first()

        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None
