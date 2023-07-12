from rest_framework import generics, authentication, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAdminUser
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.contrib.sites.shortcuts import get_current_site

from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator

from User.serializers import (
    UserSerializer,
    AuthTokenSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    UserLogoutSerializer,
)
from User.models import UserModel

class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system."""
    serializer_class = UserSerializer
    
class ConfirmEmailView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None
        
        if user and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Email successfully confirmed.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid activation link.'}, status=status.HTTP_400_BAD_REQUEST)


class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authicated user."""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Retrieve and return the authicated user."""
        return self.request.user


class UserListCreateView(generics.ListCreateAPIView):
    """Manage all the users."""
    permission_classes = [IsAdminUser]
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer

class UserRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """Manage all the users."""
    permission_classes = [IsAdminUser]
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer
    
class UserLogoutView(APIView):
    """Manage User Logout functionality"""
    serializer_class = UserLogoutSerializer
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        refresh_token = serializer.save()
        token = RefreshToken(refresh_token)

        # Blacklist the refresh token to invalidate it
        token.blacklist()

        return Response({'message': 'Logged out successfully'})
    

class PasswordChangeView(APIView):
    """Manage User Password Change functionality"""
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(request, username=request.user.username, password=serializer.validated_data['old_password'])

        if user is not None:
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            update_session_auth_hash(request, user)  
            return Response({'message': 'Password changed successfully.'}, status = status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Incorrect old password.'}, status= status.HTTP_400_BAD_REQUEST)
        

class PasswordResetView(APIView):
    """Manage the creation of link for password reset functionality"""
    serializer_class = PasswordResetSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        email = serializer.validated_data['email']
        user = UserModel.objects.get(email=email)
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(self.request)
        reset_link = f'http://{current_site.domain}/password-reset/{user.id}/{token}/'

        # Send the password reset email with the generated token and reset link
        send_mail(
            'Password Reset',
            f'Please click the following link to reset your password: {reset_link}',
            'im.smart093@gmail.com',
            [email],
            fail_silently=False,
        )

        return Response({'message': 'Password reset email sent.'}, status = status.HTTP_302_FOUND)
    


class PasswordResetConfirmView(APIView):
    """Manage User Password Resetting functionality"""
    serializer_class = PasswordResetConfirmSerializer
    def post(self, request, id, token):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = UserModel.objects.get(id=id)
        except User.DoesNotExist:
            return Response({'message': 'Invalid user.'}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

        new_password = serializer.validated_data['new_password']
        user.password = make_password(new_password)
        user.save()
        return Response({'message': 'Password reset successfully.'},status = status.HTTP_201_CREATED)