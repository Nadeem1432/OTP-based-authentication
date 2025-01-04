from django.contrib import admin
from .models import *


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email','is_verified']

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user','gender','dob']

@admin.register(TextMessage)
class TextMessageAdmin(admin.ModelAdmin):
    list_display = ['user','text','timestamp']

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin)    :
    list_display = ['email','created_at','otp']