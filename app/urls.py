from django.urls import path
from .views import *
urlpatterns = [
    path('registration/', RegisterUserView.as_view()),
    path('sign-in/', SignInView.as_view()),
    path('log-in/', LogInView.as_view()),
    path('otp_verify/', OTPVerificationView.as_view()),
    path('profile/', UserProfileView.as_view()),
]

