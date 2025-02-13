from rest_framework import views
from rest_framework.response import Response
from .models import Payment
from .serializers import PaymentSerializer
from django.shortcuts import render

class PaymentCreateView(views.APIView):
    def post(self, request):
        # Implement transaction logic
        pass

def paymentapp(request):
    return render(request, 'fashion.html')