# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# from .models import CustomUser


# @admin.register(CustomUser)
# class UserAdmin(BaseUserAdmin):

#     fieldsets = (
#         (None, {"fields": ("username", "password")}),
#         (
#             "Personal info",
#             {"fields": ("full_name", "email", "phone_number", "gender", "picture")},
#         ),
#         (
#             "Permissions",
#             {
#                 "fields": (
#                     "is_active",
#                     "is_staff",
#                     "is_superuser",
#                     "groups",
#                     "user_permissions",
#                 )
#             },
#         ),
#         ("Important dates", {"fields": ["last_login", "date_joined"]}),
#     )

#     add_fieldsets = (
#         (
#             "My User",
#             {
#                 "classes": ("wide",),
#                 "fields": ("username", "email", "full_name", "password1", "password2"),
#             },
#         ),
#     )

#     list_display = ("username", "email", "is_superuser")
#     search_fields = ("username", "email", "full_name", "phone_number")
#     readonly_fields = ["date_joined", "last_login"]
#     ordering = ["id"]
#     filter_horizontal = ("groups", "user_permissions")

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import CustomUser, Profile


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = "Profile"
    fk_name = "user"


@admin.register(CustomUser)
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)

    fieldsets = (
        (None, {"fields": ("username", "password")}),
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
                "fields": ("username", "email", "password1", "password2"),
            },
        ),
    )

    list_display = ("username", "email", "is_superuser")
    search_fields = ("username", "email")
    readonly_fields = ["date_joined", "last_login"]
    ordering = ["id"]
    filter_horizontal = ("groups", "user_permissions")


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "full_name", "email_verified")
    search_fields = ("user__username", "full_name", "user__email", "phone_number")
    list_filter = ("gender", "email_verified")
