import datetime

from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from rest_framework.validators import UniqueValidator
from rest_framework import authentication
from django.utils.timezone import make_aware

from jwt_auth.tokens import RefreshToken, AccessToken
from jwt_auth.models import BlacklistedToken

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

        if BlacklistedToken.objects.filter(jti=payload.get('jti')).exists():
            raise serializers.ValidationError('Token already exist in blacklist')

        BlacklistedToken.objects.create(
            token=token,
            jti=payload.get('jti'),
            user_id=payload.get('uid'),
            created_at=make_aware(datetime.datetime.fromtimestamp(payload.get('iat'))),
            expires_at=make_aware(datetime.datetime.fromtimestamp(payload.get('exp')))
        )

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
        if BlacklistedToken.objects.filter(jti=payload.get('jti')).exists():
            raise serializers.ValidationError('Token already exist in blacklist')

        BlacklistedToken.objects.create(
            token=token,
            jti=payload.get('jti'),
            user_id=payload.get('uid'),
            created_at=make_aware(datetime.datetime.fromtimestamp(payload.get('iat'))),
            expires_at=make_aware(datetime.datetime.fromtimestamp(payload.get('exp')))
        )

        request = self.context.get("request")
        user = request.user

        if user.id != payload.get('uid'):
            raise serializers.ValidationError('User ID mismatch')

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})
        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = datetime.datetime.utcnow() + AccessToken.expire_time
        data['refresh_expire'] = datetime.datetime.utcnow() + RefreshToken.expire_time
        data['uid'] = user.id

        return data
