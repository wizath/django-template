# Generated by Django 4.1.5 on 2023-01-06 23:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("jwt_auth", "0003_blacklistedtoken"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserRefreshToken",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("token", models.TextField()),
                ("jti", models.CharField(max_length=255, unique=True)),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField()),
                ("blacklisted_at", models.DateTimeField(blank=True, null=True)),
                ("blacklisted", models.BooleanField(default=False)),
                ("ip_address", models.CharField(blank=True, max_length=39)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.DeleteModel(
            name="BlacklistedToken",
        ),
    ]
