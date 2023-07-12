from django.contrib.auth import (
    get_user_model,
    authenticate,
)
# from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers
from .models import  UserModel

from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user object."""
    
    class Meta:
        model = get_user_model()
        fields = fields = [
            'email', 'password','username', 'firstName', 'lastName', 'gender',
            'phone', 'birthDate', 'avatar','street', 'city', 'postalCode', 'state', 
            'primary', 'label' 
        ]
        extra_kwargs = {'password': {'write_only': True}}


    def create(self, validated_data):
        """Create and return a user with encrypted password."""
        user = UserModel.objects.create_user(**validated_data)
        
        # Generate a unique token for email confirmation
        token = default_token_generator.make_token(user)
        
        # Build the email confirmation URL
        current_site = get_current_site(self.context['request'])
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        confirmation_url = f"http://{current_site.domain}/confirm-email/{uid}/{token}/"
        
        # Render the email template
        email_subject = 'Confirm your email'
        email_body = render_to_string('confirmation_email.html', {
            'user': user,
            'confirmation_url': confirmation_url,
        })
        
        # Send the email
        send_mail(email_subject, email_body, "im.smart093@gmail.com", [user.email])
        
        return user

    def update(self, instance, validated_data):
        """Update and return user"""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user auth token."""
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False,
    )

    def validate(self, attrs):
        """Validate and authenicate the user."""
        email = attrs.get('email')
        password = attrs.get('password')
        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password,
        )
        if not user:
            msg = ('Unable to authenticate with provided credentials.')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class UserLogoutSerializer(serializers.Serializer):
    """Serializer for the user Logout."""
    refresh_token = serializers.CharField(required=True)
    
        
class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for the user password Change"""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match.")
        return data
    
class PasswordResetSerializer(serializers.Serializer):
    """Serializer for the user password reset link generator"""
    email = serializers.EmailField(required=True)

    def validate_email(self, email):
        User = get_user_model()
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email address not found.")
        return email

    def save(self):
        email = self.validated_data['email']
        user = UserModel.objects.get(email=email)
        token = default_token_generator.make_token(user)
        print(token)
        

class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for the user password reset confirmation"""
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match.")
        return data