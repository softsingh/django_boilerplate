from django.db import models


class Gender(models.TextChoices):
    MALE = "male", "Male"
    FEMALE = "female", "Female"
    THIRD_GENDER = "third_gender", "Third Gender"
