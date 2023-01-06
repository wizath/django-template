import datetime

from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from jwt_auth.tokens import RefreshToken, AccessToken

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)
            if not user:
                raise serializers.ValidationError('Unable to log in with provided credentials', code='authorization')
        else:
            raise serializers.ValidationError('Must include "username" and "password"', code='authorization')

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})
        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['refresh_expire'] = datetime.datetime.utcnow() + RefreshToken.expire_time
        data['uid'] = user.id

        return data
