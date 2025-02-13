from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProductViewSet, shopapp

router = DefaultRouter()
router.register(r'products', ProductViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('shopapp/', shopapp, name='shop'),
    path('fashion/',shopapp,name='fashion'),
    
]
