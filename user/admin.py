from django.contrib import admin
from user.models import User, ResetPasswordToken

admin.site.register(User)
admin.site.register(ResetPasswordToken)
