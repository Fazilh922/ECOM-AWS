from django.urls import path, include
from rest_framework.routers import DefaultRouter


urlpatterns = [
    path('', include(router.urls)),
    path('deliveryapp/', deliveryapp, name='delivery'),
]