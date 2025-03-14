from datetime import timedelta
from django.db import models
from django.contrib.auth import get_user_model
import random
import string

# Custom User model (if you're using it)
class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    # Add any other custom fields if needed
    def __str__(self):
        return self.username

# OTP Model to store the OTP
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP for {self.user.username}"

    def is_expired(self):
        # If OTP was generated more than 10 minutes ago, it's expired
        from django.utils import timezone
        return self.created_at + timedelta(minutes=10) < timezone.now()
