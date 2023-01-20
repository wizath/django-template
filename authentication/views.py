from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.backends import JWTRefreshAuthentication, JWTRefreshCookieAuthentication
from authentication.backends import get_authentication_token
from authentication.serializers import AccessTokenSerializer, RefreshTokenSerializer


class AccessTokenAPIView(APIView):
    serializer_class = AccessTokenSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTRefreshAuthentication, JWTRefreshCookieAuthentication)

    def post(self, request):
        cookie_token = request.COOKIES.get('refresh_token', None)
        request_token = get_authentication_token('Bearer', request)
        token = cookie_token if cookie_token is not None else request_token

        serializer = self.serializer_class(data={'token': token}, context={'request': request})
        serializer.is_valid(raise_exception=True)

        serializer_data = serializer.validated_data
        access_expiration = serializer_data['access_expire']

        response_data = {
            'uid': serializer_data['uid'],
            'access_token': serializer_data['access_token'],
            'access_expire': int(access_expiration.timestamp()),
        }

        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie('access_token',
                            serializer_data['access_token'],
                            expires=access_expiration,
                            httponly=True)

        return response


class RefreshTokenAPIView(APIView):
    serializer_class = RefreshTokenSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTRefreshAuthentication, JWTRefreshCookieAuthentication)

    def post(self, request):
        cookie_token = request.COOKIES.get('refresh_token', None)
        request_token = get_authentication_token('Bearer', request)
        token = cookie_token if cookie_token is not None else request_token

        serializer = self.serializer_class(data={'token': token}, context={'request': request})
        serializer.is_valid(raise_exception=True)

        serializer_data = serializer.validated_data
        access_expiration = serializer_data['access_expire']
        refresh_expiration = serializer_data['refresh_expire']

        response_data = {
            'uid': serializer_data['uid'],
            'access_token': serializer_data['access_token'],
            'refresh_token': serializer_data['refresh_token'],
            'access_expire': int(access_expiration.timestamp()),
            'refresh_expire': int(refresh_expiration.timestamp())
        }

        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie('access_token',
                            serializer_data['access_token'],
                            expires=access_expiration,
                            httponly=True)

        response.set_cookie('refresh_token',
                            serializer_data['refresh_token'],
                            expires=refresh_expiration,
                            httponly=True)

        return response


class VerifyAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({'user_id': request.user.id})
