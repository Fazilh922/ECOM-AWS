from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import logging
from django.utils.decorators import method_decorator
from django.http import QueryDict 
from .serializers import LoginSerializer
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect



from .serializers import (
    LoginSerializer,
    ForgotPasswordSerializer,
    UserSerializer,
    LoginSerializer
)

logger = logging.getLogger(__name__)

User = get_user_model()

# View for user registration
class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

# View for user login
class UserLoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

# View for forgot password
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

# Renaming the login view to avoid conflicts
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to index page after successful login
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'login.html')  # Re-render login page on failure

# User creation view
class UserCreateView(views.APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Login view
@method_decorator(csrf_exempt, name='dispatch')

class LoginView(views.APIView):
    http_method_names = ['post']  # Allow only POST requests

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                    },
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    "redirect_url": "/home/",  # Redirect URL after successful login
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

# User registration view
@csrf_exempt  # Consider removing CSRF exemption if possible
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))  # Parse JSON data
        logger.info(f"Received Data: {data}")

        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not name or not email or not password or not confirm_password:
            return JsonResponse({'error': 'All fields are required.'}, status=400)
        
        if password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match.'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email is already registered.'}, status=400)

        user = User.objects.create(
            username=name,
            email=email,
            password=make_password(password),
            first_name=name,
        )

        return JsonResponse({'message': 'Registration successful. Please log in.'}, status=201)
    
    return render(request, 'register.html')

# Forgot password view
def forgot_password(request):
    if request.method == 'POST':
        identifier = request.POST.get('identifier')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not identifier or not new_password or not confirm_password:
            messages.error(request, "All fields are required.")
            return redirect('forgot_password')

        try:
            if '@' in identifier:
                user = User.objects.get(email=identifier)
            else:
                user = User.objects.get(profile__phone=identifier)
        except User.DoesNotExist:
            messages.error(request, "No user found with this information.")
            return redirect('forgot_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('forgot_password')

        user.set_password(new_password)
        user.save()

        send_mail(
            'Password Reset Successful',
            'Your password has been successfully reset.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        messages.success(request, "Password reset successfully. You can now log in.")
        return redirect('login')
    
    return render(request, 'forgot.html')

# Home page view
def index(request):
    return render(request, 'index.html')

# Reset password view
@csrf_exempt  # Consider removing CSRF exemption if possible
def reset_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        identifier = data.get('identifier')
        code = data.get('code')
        new_password = data.get('new_password')

        if identifier and code and new_password:
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'message': 'Invalid input data'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'})
