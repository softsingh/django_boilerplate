from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile

import os
import uuid
from PIL import Image

from .managers import CustomUserManager


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model"""

    GENDER_CHOICES = [
        ("male", "Male"),
        ("female", "Female"),
        ("third_gender", "Third Gender"),
    ]

    username = models.CharField(max_length=255, unique=True)
    full_name = models.CharField(max_length=255, blank=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True, blank=True, null=True)
    gender = models.CharField(max_length=12, choices=GENDER_CHOICES, default="male")
    picture = models.ImageField(upload_to="avatars", blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    groups = models.ManyToManyField(
        "auth.Group",
        related_name="user_set",
        blank=True,
        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="user_set",
        blank=True,
        help_text="Specific permissions for this user.",
    )
    remarks = models.TextField(blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    objects = CustomUserManager()

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
                pass  # No old instance, likely a new user

        if self.picture:
            # Validate file extension
            ext = os.path.splitext(self.picture.name)[1].lower()
            if ext not in [".jpg", ".jpeg", ".png", ".gif"]:
                raise ValidationError("Only JPG, PNG, and GIF images are allowed.")

            # Validate file size
            if self.picture.size > 100 * 1024:  # 100 KB
                raise ValidationError(
                    "Image file size must be less than or equal to 100KB."
                )

            # Check file signature and dimensions
            try:
                img = Image.open(self.picture)
                img.verify()
                width, height = img.size

                if width != height:
                    raise ValidationError(
                        "Image must be square (width and height should be equal)."
                    )
                if width > 200 or height > 200:
                    raise ValidationError(
                        "Image dimensions must not exceed 200x200 pixels."
                    )

            except Exception:
                raise ValidationError("Invalid image file")

    def save(self, *args, **kwargs):
        """
        Overwrite the default method save() to resize the profile picture
        before save using Pillow.
        """

        # # First account created must be superuser
        # is_new = self._state.adding and not self.pk

        # if is_new and CustomUser.objects.count() == 0:
        #     self.is_superuser = True
        #     self.is_staff = True

        self.full_clean()

        # If there's a new uploaded file (in memory or temp location)
        if self.picture and not self._state.adding:
            old_instance = CustomUser.objects.filter(pk=self.pk).first()
            if old_instance and old_instance.picture != self.picture:
                # New picture uploaded — rename it
                ext = os.path.splitext(self.picture.name)[1]  # Get extension
                new_name = f"{self.username}_{uuid.uuid4().hex[:8]}{ext}"

                # Read content from uploaded file
                self.picture.file.seek(0)
                content = ContentFile(self.picture.file.read())

                # Replace the field with new name and content (save=False avoids writing now)
                self.picture.save(new_name, content, save=False)

        super().save(*args, **kwargs)

        # if self.picture:
        #     img = Image.open(self.picture.path)

        #     if img.height > 200 or img.width > 200:
        #         img_size = (200, 200)
        #         img.thumbnail(img_size)
        #         img.save(self.picture.path)

    class Meta:
        default_permissions = (
            []
        )  # This prevents 'add', 'change', 'delete', 'view' profile permissions
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
        verbose_name = "Profile"
        verbose_name_plural = "Profiles"
        db_table = "user"

    def __str__(self):
        return self.username
