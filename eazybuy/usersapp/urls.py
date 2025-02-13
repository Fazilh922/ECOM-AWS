from django.urls import path
from . import views
from .views import reset_password, UserCreateView, LoginView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

# Redirect root URL to 'index'
def home_redirect(request):
    return redirect("index")  # Redirects to index page

urlpatterns = [
    # API Login
    path('api/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    # JWT Token Views
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # ✅ Redirect root URL to index instead of login
    path("", home_redirect, name="home"),  # Root now redirects to index ✅

    # Pages
    path('login/', views.login_view, name='login'),  # Keep login page under /login/
    path('register/', views.register, name='register'),
    path('forgot/', views.forgot_password, name='forgot_password'),
    path('index/', views.index, name='index'),  # Ensure index exists
    path('reset-password/', reset_password, name='reset_password'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
