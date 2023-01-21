import datetime

from django.contrib.auth import get_user_model
from rest_framework import serializers

from authentication.models import UserRefreshToken
from authentication.tokens import RefreshToken, AccessToken
from authentication.utils import get_client_ip, get_user_agent

User = get_user_model()


class AccessTokenSerializer(serializers.Serializer):
    refresh_token_prefix = 'Token'
    token = serializers.CharField()

    def validate(self, data):
        token = data.get('token')
        try:
            payload = RefreshToken.decode(token)
        except:
            raise serializers.ValidationError('Invalid token')

        request = self.context.get("request")
        user = request.user

        if user.id != payload.get('uid'):
            raise serializers.ValidationError('User ID mismatch')

        access_token = AccessToken.encode({'uid': user.id})
        data['access_token'] = access_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['uid'] = user.id

        return data


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token_prefix = 'Token'
    token = serializers.CharField()

    def validate(self, data):
        token = data.get('token')
        try:
            payload = RefreshToken.decode(token)
        except:
            raise serializers.ValidationError('Invalid token')

        # blacklist old refresh token
        old_token = UserRefreshToken.objects.filter(jti=payload.get('jti'), blacklisted=False).first()
        if old_token:
            old_token.blacklist()

        request = self.context.get("request")
        user = request.user
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

        if user.id != payload.get('uid'):
            raise serializers.ValidationError('User ID mismatch')

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})

        # create refresh token db record
        UserRefreshToken.from_token(refresh_token, ip_address, user_agent)

        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['refresh_expire'] = datetime.datetime.utcnow() + RefreshToken.expire_time
        data['uid'] = user.id

        return data
