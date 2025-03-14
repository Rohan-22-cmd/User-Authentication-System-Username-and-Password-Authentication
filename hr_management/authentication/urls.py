from django.urls import path
from . import views

urlpatterns = [
    path('', views.user_login, name='user_login'),
    path('password-reset/', views.password_reset, name='password_reset'),
    path('password-reset/verify-otp/<int:user_id>/', views.verify_otp, name='verify_otp'),
    path('password-reset/reset-password/<int:user_id>/', views.reset_password, name='reset_password'),

]
