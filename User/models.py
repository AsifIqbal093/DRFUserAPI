import uuid
import os

from django.conf import settings
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)

def avatar_file_path(instance, filename):
    """Generate file path for new recipe image."""
    ext = os.path.splitext(filename)[1]
    filename = f'{uuid.uuid4()}{ext}'

    return os.path.join('uploads', 'user', filename)


# Create your models here.
class UserManager(BaseUserManager):
    """Manager for users."""

    def create_user(self, email, password=None, **extra_fields):
        """Create, save and return a new user."""
        if not email:
            raise ValueError('User must have an email!')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_adminuser(self, email, password):
        """Create, save and return a super user."""
        if not email:
            raise ValueError('User must have an email!')
        user = self.create_user(email, password)
        user.is_superuser = False
        user.is_staff = True
        user.save(using=self._db)

        return user
    
    def create_superuser(self, email, password):
        """Create, save and return a super user."""
        if not email:
            raise ValueError('User must have an email!')
        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)

        return user
   
    
class UserModel(AbstractBaseUser, PermissionsMixin):
    """User in the system."""
    # "keycloakId": "auto-generated-from-keycloak",
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255, unique=True)
    firstName = models.CharField(max_length=255)
    lastName = models.CharField(max_length=255)
    gender = models.CharField(max_length=255)
    phone = PhoneNumberField()
    birthDate = models.DateField(auto_now_add = True)
    avatar = models.ImageField(null=True, upload_to=avatar_file_path)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    createdAt = models.DateTimeField(auto_now_add=True)
    modifiedAt = models.DateTimeField(auto_now_add=True)
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    postalCode = models.IntegerField()
    state = models.CharField(max_length=20)
    primary = models.CharField(max_length=255)
    label = models.CharField(max_length=255) 
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    

  