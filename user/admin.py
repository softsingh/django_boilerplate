from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class UserAdmin(BaseUserAdmin):

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            "Personal info",
            {"fields": ("full_name", "email", "phone_number", "gender", "picture")},
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Important dates", {"fields": ["last_login", "date_joined"]}),
    )

    add_fieldsets = (
        (
            "My User",
            {
                "classes": ("wide",),
                "fields": ("username", "email", "full_name", "password1", "password2"),
            },
        ),
    )

    list_display = ("username", "email", "is_superuser")
    search_fields = ("username", "email", "full_name", "phone_number")
    readonly_fields = ["date_joined", "last_login"]
    ordering = ["id"]
    filter_horizontal = ("groups", "user_permissions")
