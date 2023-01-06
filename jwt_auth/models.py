from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models import Model
import random


# Create your models here.
class User(AbstractUser):
    activation_code = models.CharField(max_length=6, default="000000")

    def generate_activation_code(self):
        self.activation_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
