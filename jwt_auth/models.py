import datetime
import random

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Model
from django.db.models.signals import post_save
from django.dispatch import receiver


# Create your models here.
class User(AbstractUser):
    activation_code = models.CharField(max_length=6, default="000000")

    def generate_activation_code(self):
        self.activation_code = "".join([str(random.randint(0, 9)) for _ in range(6)])


@receiver(post_save, sender=User, dispatch_uid="send_registration_confirmation")
def send_registration_email(sender, instance, **kwargs):
    pass


class BlacklistedToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    jti = models.CharField(unique=True, max_length=255)
    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    @property
    def expired(self):
        return datetime.datetime.utcnow() > self.expires_at
