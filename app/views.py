from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile, TextMessage, OTP, User, TextMessageHistory, Notification
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from .utility import send_otp
import json, traceback

class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        account_types = ('email','gmail')
        try:
            request_data = request.data if isinstance(request.data,dict) else json.loads(request.data)
            name = request_data.get('name','').strip()
            email = request_data.get('email','').strip()
            password = request_data.get('password','').strip()
            account_type = request_data.get('account_type','').strip()
            if not all([email,password]):
                raise ValueError('Email & Password required feilds.')
            if account_type not in account_types:
                raise ValueError(f'account_type required field , It should be `{'/'.join(account_types)}` only.')
            user_obj = User.objects.filter(email=email,username=email)

            if account_type == 'gmail':
                if user_obj.filter(is_active=True,is_verified=True).exists():
                    user = user_obj.last()
                elif user_obj.filter(is_active=True,is_verified=False).exists():
                    user = user_obj.last()
                    user.is_active =True
                    user.is_verified =True
                    user.save()
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
                                                    is_active=True,
                                                    is_verified=True,
                                                    misc=misc)
                    UserProfile.objects.create(user=user)

                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'token': str(refresh.access_token),
                        'message': 'Email verified.','status':200}, status=status.HTTP_200_OK)

            if user_obj.filter(is_active=True,is_verified=True).exists():
                return Response({'message': 'Email already exists.','status':400}, status=status.HTTP_400_BAD_REQUEST)
            elif user_obj.filter(is_active=True,is_verified=False).exists():
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
                                                is_active=True,
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
                    return Response({'message': f'OTP sent on email `{email}`, please verify.','status':201}, status=status.HTTP_201_CREATED)

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

            if request.data.get('password'):
                request.user.set_password(request.data.get('password'))

            if request.data.get('name'):
                request.user.name = request.data.get('name')
                
            request.user.save()
            user_profile.save()
            
            return Response({'message': 'Profile updated successfully.','status':200}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'message': str(e),'status':400}, status=status.HTTP_400_BAD_REQUEST)
        
class TextMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            text_messages = TextMessage.objects.filter(user=request.user)
            serializer = TextMessageSerializer(text_messages, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e),'status':400}, status=status.HTTP_400_BAD_REQUEST)
                                   
    def post(self, request):
        try:
            text = request.data.get('text', '').strip()
            if not text:
                return Response({'message': '`text` required field!','status':400}, status=status.HTTP_400_BAD_REQUEST)

            text_message = TextMessage.objects.create(user=request.user, text=text)
            TextMessageHistory.objects.create(
                text_message=text_message,
                text=text,
                created_by=request.user,
                updated_by=request.user)

            return Response({'message': 'Text message created successfully.','status':200}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({'message': str(e),'status':400}, status=status.HTTP_400_BAD_REQUEST)

class PushNotificationView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        if not any([request.user.is_superuser,request.user.is_staff]):
            return Response({'message': 'You do not have permission to perform this action.'
                             ,'status':403}, status=status.HTTP_403_FORBIDDEN)
        email = request.data.get('email','').strip()
        message = request.data.get('message','').strip()

        if not all([email,message]):
            raise ValueError('Email & Message required feilds.')

        try:
            user = User.objects.get(username=email,email=email,is_verified=True)

            # Create the notification
            notification = Notification.objects.create(user=user, message=message)
            return Response({'message': 'Notification pushed successfully.', 'status':201}, status=status.HTTP_201_CREATED)

        except User.DoesNotExist:
            return Response({'message': 'User not found.','status':404}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e),'status':400}, status=status.HTTP_400_BAD_REQUEST)

class GetNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        notifications = Notification.objects.filter(user=user)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
