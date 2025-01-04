from django.shortcuts import render, HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile, TextMessage, OTP, User
from django.contrib.auth import authenticate
import random
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

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
            otp_obj.created_at = datetime.now()
            otp_obj.save()
        else:
            OTP.objects.create(email=email, otp=otp)
    return response



class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            name = request.data.get('name','').strip()
            email = request.data.get('email','').strip()
            password = request.data.get('password','').strip()

            if not all([email,password]):
                raise ValueError('Email & Password required feilds.')
            user_obj = User.objects.filter(email=email,username=email) 
            if user_obj.filter(is_active=True,is_verified=True).exists():
                return Response({'message': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)
            elif user_obj.filter(is_active=False,is_verified=False).exists():
                pass
            else:
                user = User.objects.create_user(name=name,
                                                email=email,
                                                username=email,
                                                password=password,
                                                is_active=False,
                                                is_verified=False)
                
            otp_sent = send_otp(email)
            if not otp_sent:
                user.delete()
                return Response({'message':'OTP not sent'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': f'OTP sent on email `{email}`, please verify.'}, status=status.HTTP_201_CREATED)
        except Exception as E:
            return Response({'message': f'{E}'}, status=status.HTTP_400_BAD_REQUEST)


class OTPVerificationView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            otp = request.data.get('otp')
            email = request.data.get('email')
            if not all([email,otp]):
                raise ValueError('Email & OTP required feilds.')

            otp_record = OTP.objects.filter(email=email,otp=otp)
            if not otp_record.exists():
                return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            if otp_record.last().is_expired():
                return Response({'message': 'OTP has expired.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = User.objects.create(email=email,username=email)

            user.is_active = True
            user.is_verified = True
            user.save()
            otp_record.delete()
            refresh = RefreshToken.for_user(user)
            return Response({
                'token': str(refresh.access_token),
                'message': 'OTP verified successfully.'})

        except Exception as E:
            return Response({'message': f'{E}'}, status=status.HTTP_400_BAD_REQUEST)


class SignInView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            email = request.data.get('email','').strip()
            if not email:
                raise ValueError('Email required feild.')
            otp_sent = send_otp(email)
            if not otp_sent:
                return Response({'message':'OTP not sent'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': f'OTP sent on email `{email}`, please verify.'}, status=status.HTTP_201_CREATED)
        except Exception as E:
            return Response({'message': f'{E}'}, status=status.HTTP_400_BAD_REQUEST)

class LogInView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            email = request.data.get('email','').strip()
            password = request.data.get('password','').strip()

            if not all([email,password]):
                raise ValueError('Email & Password required feilds.')
            user = authenticate(username=email, password=password)
            if not user:
                return Response({'message': 'Invalid credentials'},
                                status=status.HTTP_401_UNAUTHORIZED)
                
            if not all([user.is_verified, user.is_active]):
                    return Response({'message': 'Email not verified!'},
                        status=status.HTTP_403_FORBIDDEN)

            refresh = RefreshToken.for_user(user)
            
            return Response({
                'token': str(refresh.access_token),
                'message': 'Login successfully.'
            })
            
        except Exception as E:
            return Response({'message': f'{E}'}, status=status.HTTP_400_BAD_REQUEST)
