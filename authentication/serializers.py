# serializers.py
from rest_framework import serializers
from .models import CustomUser, UploadedFile

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'public_visibility', 'is_active', 'is_staff', 'date_joined']

class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ['id', 'user', 'title', 'file', 'price']

    # accounts/serializers.py

# from rest_framework import serializers

# class ChangePasswordSerializer(serializers.Serializer):
    # old_password = serializers.CharField(required=True)
    # new_password = serializers.CharField(required=True)

# class ResetPasswordEmailSerializer(serializers.Serializer):
    # email = serializers.EmailField(required=True)