from django.db import models
from usersapp.models import CustomUser
from shopapp.models import Product
from usersapp.base import AbstractBaseModel

class Transaction(AbstractBaseModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50, choices=[('Pending', 'Pending'), ('Completed', 'Completed')])
    transaction_date = models.DateTimeField(auto_now_add=True)
    