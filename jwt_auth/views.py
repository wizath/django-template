from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from jwt_auth.serializers import LoginSerializer, RegisterSerializer


class RegisterAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.validated_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

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
