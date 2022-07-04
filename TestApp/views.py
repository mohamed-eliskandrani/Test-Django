from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import RegisterForm, UpdateForm
from django.contrib import messages
from .models import User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_jwt.utils import jwt_payload_handler
from rest_framework_jwt.utils import jwt_encode_handler
from rest_framework_jwt.utils import jwt_response_payload_handler
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

def RegisterUser(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created successfully")
            return redirect("signin")
    else:
        form = RegisterForm()
        user_info = {"form": form}
        return render(request, "register.html", user_info)


def UpdateUser(request):

    token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
    user = getTokenUser(token)
    if user == None:
        messages.error(request, "User not logged in")
        return redirect("signin")

    if request.method == 'POST':
        if User.objects.filter(Phone=request.POST['Phone']).exists():
            user = User.objects.get(Phone=request.POST['Phone'])
            form = UpdateForm(request.POST, instance=user)
            if form.is_valid():
                form.save()
                messages.success(request, "Account updated successfully")
            return redirect("signin")
        else:
            messages.error(request, "Account does not exist")
            return redirect("update")
    else:
        form = UpdateForm()
        user_info = {"form": form}
        return render(request, "update.html", user_info)


def SignIn(request):
    if request.method == "POST":
        phone = request.POST.get('Phone')
        password = request.POST.get('password')

        try:
            user = User.objects.get(Phone=phone)
            if user.check_password(password):
                payload = jwt_payload_handler(user)
                token = jwt_encode_handler(payload)
                response_payload = jwt_response_payload_handler(
                    token, user, request=request)
                response = request.POST.get(
                    "http://0.0.0.0:8001/api/jwt-verify/", {"token": token})
                response = JsonResponse(
                    {'msg': "token is verified", 'token': response_payload['token']}, safe=False)
                return redirect("loggedin")
            return redirect("signin")

        except ObjectDoesNotExist:
            messages.info(request, "User does not exist")
            return redirect("signin")
    else:
        return render(request, "signin.html")


def LoggedIn(request):

    token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
    user = getTokenUser(token)

    if user == None:
        messages.error(request, "User not logged in")
        return redirect("signin")

    if request.method == "POST":
        if 'Logout' in request.POST:

            if(logoutToken(token)):
                messages.success(request, "User logged out")
            else:
                messages.error(request, "User not logged in")

        if 'Delete' in request.POST:
            user.delete()
            messages.success(request, "User deleted")

        if 'Update' in request.POST:
            return redirect('update')

        return redirect("signin")
    else:
        user_info = {"current_user": user.FirstName}
        return render(request, "loggedin.html", user_info)


class HelloView(APIView):
        @method_decorator(login_required)    
        def get(self, request):
            content = {'message': 'Hello, World!'}
            return Response(content)

def logoutToken(token):
    try:
        token = RefreshToken(token)
        token.blacklist()
        return True
    except Exception as e:
        return False


def getTokenUser(token):
    try:
        data = {'token': token}
        valid_data = VerifyJSONWebTokenSerializer().validate(data)
        user = valid_data['user']
        return user
    except Exception as e:
        print("validation error", e)
        return None