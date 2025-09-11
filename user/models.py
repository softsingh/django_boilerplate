from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.files.base import ContentFile

import os
import uuid
from PIL import Image

from .managers import CustomUserManager
from .validators import validate_profile_picture


class CustomUser(AbstractUser):
    """Lightweight custom user model"""

    # Drop fields we don’t need
    first_name = None
    last_name = None

    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)

    # is_active = models.BooleanField(default=True)
    # is_staff = models.BooleanField(default=False)
    # is_superuser = models.BooleanField(default=False)
    # date_joined = models.DateTimeField(auto_now_add=True)
    # last_login = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    objects = CustomUserManager()

    class Meta:
        default_permissions = []
        permissions = [
            ("can_view_profile", "Can view profile"),
            ("can_view_others_profile", "Can view other's profile"),
            ("can_edit_profile", "Can edit profile"),
            ("can_edit_others_profile", "Can edit other's profile"),
            ("can_change_password", "Can change password"),
            ("can_change_others_password", "Can change other's password"),
            ("can_add_user", "Can add user"),
            ("can_delete_user", "Can delete user"),
        ]
        verbose_name = "User"
        verbose_name_plural = "Users"
        db_table = "user"

    def __str__(self):
        return self.username


class Profile(models.Model):
    """Extended profile information"""

    GENDER_CHOICES = [
        ("male", "Male"),
        ("female", "Female"),
        ("third_gender", "Third Gender"),
    ]

    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, related_name="profile"
    )
    full_name = models.CharField(max_length=255, blank=True)
    phone_number = models.CharField(max_length=15, unique=True, blank=True, null=True)
    gender = models.CharField(max_length=12, choices=GENDER_CHOICES, default="male")
    picture = models.ImageField(upload_to="avatars", blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    remarks = models.TextField(blank=True, null=True)

    class Meta:
        default_permissions = []
        verbose_name = "Profile"
        verbose_name_plural = "Profiles"
        db_table = "user_profile"

    def clean(self):
        super().clean()

        if self.picture and self.pk:
            try:
                old_instance = self.__class__.objects.get(pk=self.pk)
                if (
                    old_instance.picture
                    and old_instance.picture.name == self.picture.name
                ):
                    return  # Skip validation if picture hasn't changed
            except self.__class__.DoesNotExist:
                pass  # No old instance, likely a new profile

        if self.picture:
            validate_profile_picture(self.picture)

    def save(self, *args, **kwargs):

        # # First account created must be superuser
        # is_new = self._state.adding and not self.pk

        # if is_new and CustomUser.objects.count() == 0:
        #     self.is_superuser = True
        #     self.is_staff = True

        # To fix the error phone_number already exists
        if self.phone_number == "":
            self.phone_number = None

        self.full_clean()

        if self.picture and not self._state.adding:
            old_instance = Profile.objects.filter(pk=self.pk).first()
            if old_instance and old_instance.picture != self.picture:
                ext = os.path.splitext(self.picture.name)[1]
                new_name = f"{self.user.username}_{uuid.uuid4().hex[:8]}{ext}"

                self.picture.file.seek(0)
                content = ContentFile(self.picture.file.read())
                self.picture.save(new_name, content, save=False)

        super().save(*args, **kwargs)

        # if self.picture:
        #     img = Image.open(self.picture.path)

        #     if img.height > 300 or img.width > 300:
        #         img_size = (300, 300)
        #         img.thumbnail(img_size)
        #         img.save(self.picture.path)

    def __str__(self):
        return f"Profile of {self.user.username}"
