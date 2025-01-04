from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile, TextMessage, OTP, User
from django.utils import timezone
import random

def generate_otp():
    otp = str(random.randint(100000, 999999))
    return otp

def send_otp(email):
    otp = generate_otp()
    try:
        response = send_mail(
                    'OTP',
                    f'Enter OTP {otp} to verify your email.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    )
        response = bool(response)
    except:
        response = False
    
    if response:
        otp_obj = OTP.objects.filter(email=email)
        if otp_obj.exists():
            otp_obj = otp_obj.last()
            otp_obj.otp = otp
            otp_obj.created_at = timezone.now()
            otp_obj.save()
        else:
            OTP.objects.create(email=email, otp=otp)
    return response