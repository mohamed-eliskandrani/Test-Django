from django import forms
from django.forms import ModelForm
from django import forms
from .models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class RegisterForm(ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'Phone', 'email', 'password', 'FirstName']
    
    def save(self, commit=True):
        user = super(RegisterForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user

class SignInForm(ModelForm):
    Password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['Phone', 'password']

class UpdateForm(ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['Phone','username', 'email', 'password']
    
    def save(self, commit=True):
        user = super(UpdateForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.username = self.cleaned_data["username"]
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
