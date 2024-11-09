from django.urls import path,include
from . import views


urlpatterns = [
    path("signup/", views.SignupView.as_view(), name='signup'),
    path('activate/<uidb64>/<token>/', views.ActiveAccountView.as_view(), name="activate_account"),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('token/refresh/', views.CustomTokenRefreshView.as_view(), name='refresh-token'),
    path('profile/', views.ProfileView.as_view(), name='profile')
]