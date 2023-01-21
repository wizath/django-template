import datetime

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Model
from django.utils.timezone import make_aware

from authentication.tokens import RefreshToken


class UserRefreshToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    jti = models.CharField(unique=True, max_length=255)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    blacklisted_at = models.DateTimeField(blank=True, null=True)
    blacklisted = models.BooleanField(default=False)
    ip_address = models.CharField(blank=True, max_length=39)
    user_agent = models.CharField(max_length=256, default="", blank=True)

    @staticmethod
    def from_token(token, ip_address=None, user_agent=None):
        payload = RefreshToken.decode(token)
        return UserRefreshToken.objects.create(
            token=token,
            jti=payload.get('jti'),
            user_id=payload.get('uid'),
            created_at=make_aware(datetime.datetime.fromtimestamp(payload.get('iat'))),
            expires_at=make_aware(datetime.datetime.fromtimestamp(payload.get('exp'))),
            ip_address=ip_address
        )

    @property
    def expired(self):
        return datetime.datetime.utcnow() > self.expires_at

    @property
    def is_blacklisted(self):
        return self.blacklisted

    def blacklist(self):
        self.blacklisted = True
        self.blacklisted_at = make_aware(datetime.datetime.now())
        self.save()
