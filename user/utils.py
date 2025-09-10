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
    """Common filter for user data"""

    filters = Q()

    # Status filter
    status_map = {"active": True, "disabled": False}
    if status in status_map:
        filters &= Q(is_active=status_map[status])

    # Role filter
    role_map = {"admin": True, "user": False}
    if role in role_map:
        filters &= Q(is_superuser=role_map[role])

    # Search query
    if query:
        filters &= (
            Q(username__icontains=query)
            | Q(profile__full_name__icontains=query)
            | Q(email__icontains=query)
            | Q(profile__phone_number__icontains=query)
            | Q(profile__remarks__icontains=query)
        )

    return queryset.filter(filters)
