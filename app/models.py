from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
import os
from django.utils import timezone


class User(AbstractUser):
    is_verified = models.BooleanField(default=False)
    name = models.CharField(max_length=255, null=True, blank=True)
    misc = models.JSONField()
    def __str__(self):
        return str(self.id)+"-"+str(self.email)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    photo = models.ImageField(upload_to='profile_photos/', null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    def __str__(self):
        return str(self.user.email)

class TextMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return str(self.user.email)

class OTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=5)  # OTP valid for 5 minutes
    def __str__(self):
        return str(self.email)
    