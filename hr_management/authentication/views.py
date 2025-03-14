from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import User
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
import random
from django.conf import settings

# Handle user login
def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("dashboard")  # Redirect to some dashboard page after login
        else:
            return JsonResponse({"message": "Invalid username or password"}, status=400)
    return render(request, "authentication/login.html")


from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
import random
from django.contrib import messages

def password_reset(request):
    if request.method == "POST":
        email = request.POST.get("email")  # Get the entered email
        
        try:
            # Check if the user exists with this email
            user = User.objects.get(email=email)
            
            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)
            user.otp = str(otp)  # Save OTP to the user model
            user.save()

            # Send OTP to user's email
            send_mail(
                'Password Reset OTP',
                f'Your OTP for resetting your password is {otp}',
                'your-email@gmail.com',  # Replace with your Gmail address
                [email],  # Recipient email
                fail_silently=False,
            )

            # Redirect user to OTP verification page
            return redirect('verify_otp', user_id=user.id)
        
        except User.DoesNotExist:
            # If user does not exist, show error message
            messages.error(request, "If the email is registered, you will receive an OTP.")
            return redirect('password_reset')

    # If the request method is GET, render the password reset form
    return render(request, "authentication/password_reset.html")


from django.core.mail import send_mail
from random import randint
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model

def send_otp_to_user(user):
    otp = str(randint(100000, 999999))  # Generate a 6-digit OTP
    user.otp = otp
    user.save()

    # Send OTP via email (using your email configuration)
    send_mail(
        'Your OTP for password reset',
        f'Your OTP is {otp}',
        'from@example.com',
        [user.email],
        fail_silently=False,
    )
# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from .models import PasswordResetOTP
from datetime import timedelta
from django.utils import timezone

# View to verify OTP and allow password reset
def verify_otp(request, user_id):
    user = get_user_model().objects.get(id=user_id)
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        try:
            otp_instance = PasswordResetOTP.objects.get(user=user, otp=otp_entered)

            # Check OTP expiration (optional)
            if otp_instance.created_at + timedelta(minutes=10) < timezone.now():
                messages.error(request, "OTP has expired. Please request a new OTP.")
                return render(request, 'authentication/verify_otp.html', {'user_id': user.id})

            # OTP is valid, redirect to reset password page
            return redirect('reset_password', user_id=user.id)

        except PasswordResetOTP.DoesNotExist:
            messages.error(request, "Invalid OTP. Please try again.")
    return render(request, 'authentication/verify_otp.html', {'user_id': user.id})

# View to reset the password after OTP is verified
def reset_password(request, user_id):
    user = get_user_model().objects.get(id=user_id)
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        user.set_password(new_password)  # Set the new password
        user.save()
        messages.success(request, "Your password has been reset successfully!")
        return redirect('login')  # Redirect to the login page
    return render(request, 'authentication/reset_password.html', {'user_id': user.id})
