# validators.py
import os
from django.core.exceptions import ValidationError
from PIL import Image


def validate_profile_picture(picture):
    if not picture:
        return

    # Validate file extension
    ext = os.path.splitext(picture.name)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".gif"]:
        raise ValidationError("Only JPG, PNG, and GIF images are allowed.")

    # Validate file size (<= 100 KB)
    if picture.size > 100 * 1024:
        raise ValidationError("Image file size must be less than or equal to 100KB.")

    # Validate dimensions
    try:
        img = Image.open(picture)
        width, height = img.size
        if width != height:
            raise ValidationError("Image must be square (width = height).")
        # if width > 200 or height > 200:
        #     raise ValidationError("Image dimensions must not exceed 200x200 pixels.")
    except Exception:
        raise ValidationError("Invalid image file.")
