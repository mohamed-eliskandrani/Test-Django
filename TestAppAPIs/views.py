from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from .models import User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_jwt.utils import jwt_payload_handler
from rest_framework_jwt.utils import jwt_encode_handler
from rest_framework_jwt.utils import jwt_response_payload_handler
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from django.contrib.auth.hashers import make_password
from TestApp.views import getTokenUser

class SignIn(APIView):
    permission_classes = ()
    def post(self, request):
        phone = request.POST.get('Phone')
        password = request.POST.get('password')
        user = getUserFromLoginCredentials(phone, password)
        if user is not None:
            return Response({"token": generateUserToken(user)})
        return Response({"message": "Invalid"})       

class Register(APIView):
    permission_classes = ()
    def post(self,request):
        user = createUserDataFromRequest(request)
        if user is None: 
            return Response({"message": "User already registered"})
        return Response({"message": "User successfully registered"})

class Update(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        user = getTokenUser(token)
        if user == None:
            messages.error(request, "User not logged in")
            return redirect("signin")
        print(user.Phone)
        if request.POST.get('password') is not None:
            user.set_password(request.POST.get('password'))
        if request.POST.get('username') is not None:
            user.username = request.POST.get('username')
        if request.POST.get('FirstName') is not None:
            user.FirstName = request.POST.get('FirstName')
        if request.POST.get('LastName') is not None:
            user.LastName = request.POST.get('LastName')
        if request.POST.get('Address') is not None:
            user.Address = request.POST.get('Address')
        if request.POST.get('email') is not None:
            user.email = request.POST.get('email')
        user.save()
        return Response({"message": "User successfully updated"})

class Delete(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        user = getTokenUser(token)
        if user is None:
             return Response({"message": "User does not exist"})
        user.delete()
        return Response({"message": "User successfully deleted"})

def getUserFromLoginCredentials(phone, password):
    try:
        user = User.objects.get(Phone=phone)
        if user.check_password(password):
            return user
        else:
            return None
    except ObjectDoesNotExist:
        return None

def generateUserToken(user):
    payload = jwt_payload_handler(user)
    token = jwt_encode_handler(payload)

    valid_data = VerifyJSONWebTokenSerializer().validate({'token': token})
    user = valid_data['user']
    return token

def createUserDataFromRequest(request):
    FirstName = request.POST.get('FirstName')
    LastName = request.POST.get('LastName')
    Phone = request.POST.get('Phone')
    Address = request.POST.get('Address')
    email = request.POST.get('email')
    username = request.POST.get('username')
    password = request.POST.get('password')

    if isExistingUser(Phone):
        return None
    user = User.objects.create(username=username, password=make_password(password), FirstName= FirstName, LastName= LastName, Phone = Phone, email=email, Address = Address)
    user.set_password(password)
    user.save
    return user

def isExistingUser(Phone):
    try:
        user = User.objects.get(Phone=Phone)
        if user is not None:
            return True
    except ObjectDoesNotExist:
        return False
    return False