import os
import random

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.mail import send_mail
from django.db import models
from django.db.models import Model
from django.db.models.signals import post_save
from django.dispatch import receiver, Signal
from django.template.loader import render_to_string

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

    @staticmethod
    def generate_activation_code():
        return "".join([str(random.randint(0, 9)) for _ in range(6)])


@receiver(reset_password_token_created, dispatch_uid="reset_password_token_created")
def send_password_reset_signal(sender, instance, **kwargs):
    send_password_reset_email(instance)


@receiver(post_save, sender=User, dispatch_uid="send_registration_confirmation")
def send_registration_email(sender, instance, created=False, **kwargs):
    if created:
        send_activation_email(instance)


def send_activation_email(user: User):
    plain_message = f'Welcome on board {user.username}, your activation code is {user.activation_code}'
    html_message = render_to_string('account_activation_email.html', {'content': plain_message})

    send_mail(
        'Activation code',
        plain_message,
        'noreply@template.com',
        [user.email],
        html_message=html_message,
    )


def send_password_reset_email(token: ResetPasswordToken):
    plain_message = f'Welcome {token.user.username}, your password reset code is {token.token}'
    html_message = render_to_string('password_reset_email.html', {'content': plain_message})

    send_mail(
        'Password reset token',
        plain_message,
        'noreply@template.com',
        [token.user.email],
        html_message=html_message,
    )
