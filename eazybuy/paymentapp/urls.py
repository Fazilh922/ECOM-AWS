from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import  paymentapp


urlpatterns = [
    path('', include(router.urls)),
    path('paymentapp/', paymentapp, name='pay'),
]