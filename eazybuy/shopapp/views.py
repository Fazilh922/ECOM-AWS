import logging
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from .models import Product
from .serializers import ProductSerializer
from django.shortcuts import render

logger = logging.getLogger(__name__)

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    def retrieve(self, request, *args, **kwargs):
        try:
            product = self.get_object()
            if product.is_deleted:
                raise NotFound("Product not found.")
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error retrieving product: {str(e)}")
            raise



def shopapp(request):
    return render(request, 'home.html')

def fashion(request):

    ph=Product.objects.filter()
    return render(request,'customer/fashion.html',{'product':ph})

def home_view(request):
    return render(request, "home.html")  # Ensure the correct template path