from django.contrib import admin
from jwt_auth.models import User, UserRefreshToken

# Register your models here.
admin.site.register(User)
admin.site.register(UserRefreshToken)
