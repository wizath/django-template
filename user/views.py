from django.urls import reverse
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.backends import JWTRefreshAuthentication, JWTRefreshCookieAuthentication
from authentication.backends import get_authentication_token
from user.serializers import LoginSerializer, RegisterSerializer, LogoutSerializer


class LogoutAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTRefreshCookieAuthentication, JWTRefreshAuthentication)

    def post(self, request):
        cookie_token = request.COOKIES.get('refresh_token', None)
        request_token = get_authentication_token('Bearer', request)
        token = cookie_token if cookie_token is not None else request_token

        serializer = LogoutSerializer(data={'token': token})
        if serializer.is_valid():
            response = Response({}, status=status.HTTP_200_OK)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    authentication_classes = ()

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    authentication_classes = ()

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
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
                            secure=True,
                            httponly=True)

        response.set_cookie('refresh_token',
                            serializer_data['refresh_token'],
                            expires=refresh_expiration,
                            secure=True, # todo: set if not debug mode
                            httponly=True)

        return response
