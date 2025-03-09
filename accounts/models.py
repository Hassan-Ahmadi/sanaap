from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from accounts.managers import CustomUserManager
from datetime import datetime, timedelta
from django.conf import settings


class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_("email address"), unique=True)
    is_email_verified = models.BooleanField(default=False)
    # email_otp = models.CharField(max_length=6, null=True, blank=True)
    # otp_created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
