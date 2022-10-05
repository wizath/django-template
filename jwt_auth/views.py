from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        return Response({'status': 'ok'}, status=status.HTTP_200_OK)


class VerifyAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({'user_id': request.user.id})
