from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    REQUIRED_FIELDS = ['email', 'username', 'password']
    USERNAME_FIELD = 'Phone'
    FirstName = models.CharField(max_length=100)
    LastName = models.CharField(max_length=100)
    Phone = models.CharField(max_length=20, unique=True)
    Image = models.ImageField(upload_to='images', default=None, blank=True)
    Address = models.CharField(max_length=200, blank=True)