from django.contrib.auth.models import AbstractUser
from django.db import models
from .base import AbstractBaseModel

class CustomUser(AbstractUser, AbstractBaseModel):
    is_customer = models.BooleanField(default=False)
    phone = models.CharField(max_length=15, blank=True, null=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username  # Removed comma to return a proper string