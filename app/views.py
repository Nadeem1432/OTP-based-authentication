from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile, TextMessage, OTP, User
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserProfileSerializer
from .utility import send_otp
import json, traceback

class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        accont_types = ('email','gmail')
        try:
            request_data = request.data if isinstance(request.data,dict) else json.loads(request.data)
            name = request_data.get('name','').strip()
            email = request_data.get('email','').strip()
            password = request_data.get('password','').strip()
            accont_type = request_data.get('accont_type','').strip()
            if not all([email,password]):
                raise ValueError('Email & Password required feilds.')
            if accont_type not in accont_types:
                raise ValueError(f'accont_type required field , It should be `{'/'.join(accont_types)}` only.')
            user_obj = User.objects.filter(email=email,username=email) 
            if user_obj.filter(is_active=True,is_verified=True).exists():
                return Response({'message': 'Email already exists.','status':400}, status=status.HTTP_400_BAD_REQUEST)
            elif user_obj.filter(is_active=False,is_verified=False).exists():
                user = user_obj.last()
            else:
                # misc data
                request_data.pop("password")
                request_data.pop("email")
                request_data.pop("name")
                misc = request_data

                user = User.objects.create_user(name=name,
                                                email=email,
                                                username=email,
                                                password=password,
                                                is_active=False,
                                                is_verified=False,
                                                misc=misc)
                UserProfile.objects.create(user=user)
                
            otp_sent = send_otp(email)
            if not otp_sent:
                user.delete()
                return Response({'message':'OTP not sent','status':400}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': f'OTP sent on email `{email}`, please verify.','status':201}, status=status.HTTP_201_CREATED)
        except Exception as E:
            return Response({'message': f'{traceback.format_exc()}','status':400}, status=status.HTTP_400_BAD_REQUEST)


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
                return Response({'message': 'Invalid OTP','status':400}, status=status.HTTP_400_BAD_REQUEST)
            if otp_record.last().is_expired():
                return Response({'message': 'OTP has expired.','status':400}, status=status.HTTP_400_BAD_REQUEST)

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
                'message': 'OTP verified successfully.','status':200}, status=status.HTTP_200_OK)

        except Exception as E:
            return Response({'message': f'{E}','status':400}, status=status.HTTP_400_BAD_REQUEST)


class SignInView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            email = request.data.get('email','').strip()
            if not email:
                raise ValueError('Email required feild.')
            otp_sent = send_otp(email)
            if not otp_sent:
                return Response({'message':'OTP not sent','status':400}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': f'OTP sent on email `{email}`, please verify.','status':201}, status=status.HTTP_201_CREATED)
        except Exception as E:
            return Response({'message': f'{E}','status':200}, status=status.HTTP_400_BAD_REQUEST)

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
                return Response({'message': 'Invalid credentials','status':401},
                                status=status.HTTP_401_UNAUTHORIZED)
                
            if not all([user.is_verified, user.is_active]):
                    return Response({'message': 'Email not verified!','status':403},
                        status=status.HTTP_403_FORBIDDEN)

            refresh = RefreshToken.for_user(user)
            
            return Response({
                'token': str(refresh.access_token),
                'message': 'Login successfully.','status':200
            })
            
        except Exception as E:
            return Response({'message': f'{E}'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_profile = request.user.userprofile
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        try:
            user_profile = request.user.userprofile

            if 'photo' in request.data:
                user_profile.photo = request.data['photo']
            if 'gender' in request.data:
                user_profile.gender = request.data['gender']
            if 'dob' in request.data:
                user_profile.dob = request.data['dob']
            
            user_profile.save()
            
            return Response({'message': 'Profile updated successfully.','status':200}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'message': str(e),'status':400}, status=status.HTTP_400_BAD_REQUEST)