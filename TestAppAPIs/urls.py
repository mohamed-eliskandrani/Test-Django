from TestAppAPIs import views
from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token
from django.conf.urls import url

urlpatterns = [
    path('signin', views.SignIn.as_view(), name='signin'),
    path('register', views.Register.as_view(), name='register'),
    path('update', views.Update.as_view(), name='update'),
    path('delete', views.Delete.as_view(), name='delete'),
]