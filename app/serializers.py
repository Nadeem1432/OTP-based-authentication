from rest_framework import serializers
from .models import *

class UserProfileSerializer(serializers.ModelSerializer):
    email = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()

    def get_email(self,obj):
        return obj.user.email if obj.user.email else ''

    def get_name(self,obj):
        return obj.user.name if obj.user.name else ''
    
    class Meta:
        model = UserProfile
        fields = ['photo', 'gender', 'dob','email', 'name']


class TextMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = TextMessage
        fields = ('id', 'text', 'timestamp')

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ('id', 'message', 'timestamp', 'is_read')