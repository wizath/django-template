# Generated by Django 4.1.5 on 2023-01-21 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0002_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="userrefreshtoken",
            name="user_agent",
            field=models.CharField(blank=True, default="", max_length=256),
        ),
    ]
