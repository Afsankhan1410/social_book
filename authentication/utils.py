from django.conf import settings
from django.core.mail import send_mail

from .models import CustomUser


def send_email_token(email,token):
    try:
        subject = 'Email Verification'
        message = f'Hi,{CustomUser.username} click on the link to verify your email http://127.0.0.1:8000/verify/{token}'
        email_from = settings.EMAIL_HOST_USER
        
        send_mail(subject, message, email_from, [email])
        user_obj = CustomUser.objects.get(email=email)
        # user_obj.email_token
        user_obj.save()

    except Exception as e:
        print(e)
        return False

    return True