import os
import random

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Model
from django.db.models.signals import post_save
from django.dispatch import receiver, Signal

reset_password_token_created = Signal()


class ResetPasswordToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='password_reset_tokens', on_delete=models.CASCADE)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    token = models.TextField()
    ip_address = models.CharField(blank=True, max_length=39)
    user_agent = models.CharField(max_length=256, default="", blank=True)

    @staticmethod
    def generate_token():
        return os.urandom(32).hex()


class User(AbstractUser):
    activation_code = models.CharField(max_length=6, default="000000")

    def generate_activation_code(self):
        self.activation_code = "".join([str(random.randint(0, 9)) for _ in range(6)])


@receiver(reset_password_token_created, dispatch_uid="reset_password_token_created")
def send_registration_email(sender, instance, **kwargs):
    pass


@receiver(post_save, sender=User, dispatch_uid="send_registration_confirmation")
def send_registration_email(sender, instance, **kwargs):
    pass
