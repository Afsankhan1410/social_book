from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth import get_user_model
from .models import CustomUser, UploadedFile
from django.contrib.auth.forms import UserCreationForm
from django import forms

User = get_user_model()
class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = CustomUser
        fields = ("email",)


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = CustomUser
        fields = ("email",)

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['title','file','price']
