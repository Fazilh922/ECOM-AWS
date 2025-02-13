import uuid
from django.db import models
from paymentapp.models import Transaction
from usersapp.base import AbstractBaseModel


class OrderTracking(models.Model):
    id = models.BigAutoField(primary_key=True)  # Keep the existing ID
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)  # Add new UUID field

    transaction = models.OneToOneField(Transaction, on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=[('Processing', 'Processing'), ('Shipped', 'Shipped'), ('Delivered', 'Delivered')])
    updated_at = models.DateTimeField(auto_now=True)
