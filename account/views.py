from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.models import User
from account.serializers import UserRegistrationSerializer, UserLoginSerializer, ProfileViewSerializer, UserChangePasswordSerializer, SendPasswordEmailResetSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Create your views here.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderers]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({"msg": "User Register Successfully", "data": serializer.data ,'token': token},status=status.HTTP_201_CREATED)
        

class UserLoginView(APIView):
    renderer_classes = [UserRenderers]

    def post(self,request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data['email']
            password = serializer.data['password']
            user = authenticate(email=email, password=password)
            if user is None:
                return Response({"errors": {'non_field_errors': ['Email or Password is Incorrect']}}, status=status.HTTP_404_NOT_FOUND)
            token = get_tokens_for_user(user)
            return Response({"msg": "Login Successfully", 'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserProfileView(APIView):
    renderer_classes = [UserRenderers]
    permission_classes = [IsAuthenticated]

    def get(self, request, format = None):
        serializer = ProfileViewSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK) 
    

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderers]
    permission_classes = [IsAuthenticated]

    def post(self, request, format = None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg": "Password Changed Successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class SendPasswordEmailResetView(APIView):
    renderer_classes = [UserRenderers]

    def post(self, request, format = None):
        serializer = SendPasswordEmailResetSerializer(data=request.data) 
        if serializer.is_valid(raise_exception=True):
            return Response({"msg": "Password Reset link Send. Check your Registered Email"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderers]

    def post(self, request, uid, token, format = None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)