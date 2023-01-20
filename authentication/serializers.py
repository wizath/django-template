import datetime

from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from authentication.models import UserRefreshToken
from authentication.tokens import RefreshToken, AccessToken
from authentication.utils import get_client_ip

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

        request = self.context.get("request")
        ip_address = get_client_ip(request)

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})

        # create refresh token db record
        UserRefreshToken.from_token(refresh_token, ip_address)

        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['refresh_expire'] = datetime.datetime.utcnow() + RefreshToken.expire_time
        data['uid'] = user.id

        return data


class RegisterSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255, min_length=2,
                                     validators=[UniqueValidator(queryset=User.objects.all())])
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(max_length=64, min_length=8, write_only=True)
    first_name = serializers.CharField(max_length=255, min_length=4, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'password']

    def validate(self, attrs):
        return super().validate(attrs)

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            first_name=validated_data.get('first_name', ''),
        )

        user.set_password(validated_data.get('password'))
        user.generate_activation_code()
        user.is_active = False
        user.save()

        return user


class LogoutSerializer(serializers.Serializer):
    refresh_token_prefix = 'Token'
    token = serializers.CharField()

    def validate(self, attrs):
        token = attrs.get('token')
        try:
            payload = RefreshToken.decode(token)
        except:
            raise serializers.ValidationError('Invalid token')

        # blacklist old refresh token
        old_token = UserRefreshToken.objects.filter(jti=payload.get('jti'), blacklisted=False).first()
        if old_token:
            old_token.blacklist()

        return attrs


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

        if user.id != payload.get('uid'):
            raise serializers.ValidationError('User ID mismatch')

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})

        # create refresh token db record
        UserRefreshToken.from_token(refresh_token, ip_address)

        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['refresh_expire'] = datetime.datetime.utcnow() + RefreshToken.expire_time
        data['uid'] = user.id

        return data
