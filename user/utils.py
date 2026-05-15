from django.forms import ValidationError
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.urls import reverse
from django.conf import settings

from PIL import Image

from django.db.models import Q

from common.advanced_query import AdvancedQueryService

USER_ADVANCED_QUERY_CONFIG = {
    # "status": {
    #     "label": "Status",
    #     "orm": "number",
    #     "type": "int",
    #     "ui_type": "number",
    #     "operators": {"eq", "gt", "gte", "lt", "lte", "between", "in"},
    # },
    # "role": {
    #     "label": "Role",
    #     "orm": "year",
    #     "type": "int",
    #     "ui_type": "number",
    #     "operators": {"eq", "gt", "gte", "lt", "lte", "between", "in"},
    # },
    "full_name": {
        "label": "Full Name",
        "orm": "profile__full_name",
        "type": "str",
        "ui_type": "text",
        "operators": {"eq", "contains", "startswith", "endswith", "in"},
    },
    # "student_regn_no": {
    #     "label": "Registration No.",
    #     "orm": "student__regn_no",
    #     "type": "str",
    #     "ui_type": "text",
    #     "operators": {"eq", "contains", "startswith", "endswith", "in"},
    # },
    # "student_gender": {
    #     "label": "Gender",
    #     "orm": "student__gender",
    #     "type": "choice",
    #     "ui_type": "choice",
    #     "operators": {"eq", "in"},
    #     "choices": {"Male", "Female", "Other"},
    # },
    # "student_dept": {
    #     "label": "Department Code",
    #     "orm": "student__subject__dept__code",
    #     "type": "choice",
    #     "ui_type": "choice",
    #     "operators": {"eq", "in"},
    #     "choices": set(),
    # },
    # "student_subject": {
    #     "label": "Subject",
    #     "orm": "student__subject__name",
    #     "type": "str",
    #     "ui_type": "text",
    #     "operators": {"eq", "contains", "startswith", "endswith", "in"},
    # },
    # "submission_date": {
    #     "label": "Submission Date",
    #     "orm": "student__thesis_submission_date",
    #     "type": "date",
    #     "ui_type": "date",
    #     "operators": {"eq", "gt", "gte", "lt", "lte", "between"},
    # },
    "remarks": {
        "label": "Remarks",
        "orm": "profile__remarks",
        "type": "str",
        "ui_type": "text",
        "operators": {"eq", "contains", "startswith", "endswith"},
    },
}

user_advanced_query_service = AdvancedQueryService(USER_ADVANCED_QUERY_CONFIG)


def send_verification_email(self, user):
    """
    Send an email with a verification link using an external template.
    """
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    verification_link = self.request.build_absolute_uri(
        reverse("verify_email", kwargs={"uidb64": uid, "token": token})
    )

    context = {
        "user": user,
        "verification_link": verification_link,
        "PROJECT_NAME_SHORT": settings.PROJECT_NAME_SHORT,
    }

    # Load subject from external text file
    subject = render_to_string("user/verification_email_subject.txt", context).strip()

    # Load plain text email from external text file
    text_message = render_to_string("user/verification_email.txt", context)

    # Load and render the templates
    html_message = render_to_string("user/verification_email.html", context)

    # Use EmailMultiAlternatives to send both HTML and plain text versions
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_message,  # Plain text version
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email],
    )
    email.attach_alternative(html_message, "text/html")

    try:
        email.send()
    except Exception as e:
        messages.error(
            self.request,
            "Failed to send verification email. Please try again later or contact support.",
        )


def get_filtered_users(queryset, status="", role="", query=""):
    # if file_no and file_no.isdigit():
    #     queryset = queryset.filter(number=int(file_no))

    # if file_year and file_year.isdigit():
    #     queryset = queryset.filter(year=int(file_year))

    # Status filter
    status_map = {"active": True, "disabled": False}
    if status in status_map:
        queryset = queryset.filter(is_active=status_map[status])

    # Role filter
    role_map = {"admin": True, "user": False}
    if role in role_map:
        queryset = queryset.filter(is_superuser=role_map[role])

    if query:
        query = query.strip()

        if query.startswith("query:"):
            queryset = user_advanced_query_service.apply(queryset, query)
        else:
            queryset = queryset.filter(
                Q(username__icontains=query)
                | Q(profile__full_name__icontains=query)
                | Q(email__icontains=query)
                | Q(profile__phone_number__icontains=query)
                | Q(profile__remarks__icontains=query)
            ).distinct()

    return queryset


# def get_filtered_users(queryset, status="", role="", query=""):
#     """Common filter for user data"""

#     filters = Q()

#     # Status filter
#     status_map = {"active": True, "disabled": False}
#     if status in status_map:
#         filters &= Q(is_active=status_map[status])

#     # Role filter
#     role_map = {"admin": True, "user": False}
#     if role in role_map:
#         filters &= Q(is_superuser=role_map[role])

#     # Search query
#     if query:
#         filters &= (
#             Q(username__icontains=query)
#             | Q(profile__full_name__icontains=query)
#             | Q(email__icontains=query)
#             | Q(profile__phone_number__icontains=query)
#             | Q(profile__remarks__icontains=query)
#         )

#     return queryset.filter(filters)
