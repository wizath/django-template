import datetime

from django.contrib.auth import authenticate, get_user_model
from django.core import exceptions
from django.utils.timezone import make_aware
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.validators import UniqueValidator

from authentication.models import UserRefreshToken
from authentication.tokens import RefreshToken, AccessToken
from authentication.utils import get_client_ip, get_user_agent
from user.models import ResetPasswordToken, reset_password_token_created
from django.contrib.auth.password_validation import validate_password, get_password_validators

User = get_user_model()


class PasswordResetObtainTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError('Invalid email address')

        if not user.is_active:
            raise serializers.ValidationError('Invalid email address')

        if user.password_reset_tokens.all().count() > 0:
            token = user.password_reset_tokens.first()
        else:
            request = self.context.get("request")
            ip_address = get_client_ip(request)
            user_agent = get_user_agent(request)

            now = make_aware(datetime.datetime.utcnow())
            token = ResetPasswordToken.objects.create(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                token=ResetPasswordToken.generate_token(),
                created_at=now,
                expires_at=now + datetime.timedelta(hours=24)
            )
        reset_password_token_created.send(sender=self.__class__, instance=token)

        return attrs


class PasswordResetTokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        token = attrs.get('token')
        password = attrs.get('password')

        reset_password_token = ResetPasswordToken.objects.filter(token=token).first()
        if not reset_password_token:
            raise serializers.ValidationError("Invalid token")

        if make_aware(datetime.datetime.now()) > reset_password_token.expires_at:
            raise serializers.ValidationError("Invalid token")

        if not reset_password_token.user.is_active:
            raise serializers.ValidationError("Invalid user")

        try:
            validate_password(password, reset_password_token.user)
        except ValidationError as e:
            raise exceptions.ValidationError({
                'password': e.messages
            })

        # save new password
        reset_password_token.user.set_password(password)
        reset_password_token.user.save()

        # delete token
        ResetPasswordToken.objects.filter(user=reset_password_token.user).delete()

        # delete all user sessions
        tokens = UserRefreshToken.objects.filter(user=reset_password_token.user)
        [token.blacklist() for token in tokens]

        return attrs


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
        user_agent = get_user_agent(request)

        access_token = AccessToken.encode({'uid': user.id})
        refresh_token = RefreshToken.encode({'uid': user.id})

        # create refresh token db record
        UserRefreshToken.from_token(refresh_token, ip_address, user_agent)

        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        data['access_expire'] = make_aware(datetime.datetime.utcnow() + AccessToken.expire_time)
        data['refresh_expire'] = make_aware(datetime.datetime.utcnow() + RefreshToken.expire_time)
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
            activation_code=User.generate_activation_code(),
            is_active=False,
        )

        user.set_password(validated_data.get('password'))
        user.save()

        return user


class ActivateSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = attrs.get('token')

        if len(token) != 6:
            raise serializers.ValidationError("Invalid token")

        user = User.objects.filter(activation_code=token).first()
        if not user:
            raise serializers.ValidationError("Invalid token")

        if user.is_active:
            raise serializers.ValidationError("User is already active")

        # set user as active
        user.is_active = True
        user.save()

        attrs['uid'] = user.id

        return attrs


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
