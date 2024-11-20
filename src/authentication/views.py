from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .serializers import CreateUserSerializer,UserLoginSerializer,LogoutRequestSerializer, ForgotPasswordResetSerializer, ForgotPasswordSerializer
from rest_framework.response import Response
from .helpers import validation_error_handler, AuthHelper
from .tokens import account_activation_token, forogtoPasswordTokenGenerator
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import check_password 
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth.tokens import default_token_generator
from .throttle import forgotPasswordResetThrottle

User = get_user_model()

class SignupView(APIView):

    serializer_class = CreateUserSerializer

    def post(self, request, *args,**kwargs):
        request_data = request.data
        serializer = self.serializer_class(data = request_data)

        if serializer.is_valid() is False:

            return Response({
                "status" : "Error",
                "message": validation_error_handler(serializer.errors),
                "payload" : {
                    "errors" : serializers.errors
                }
            },status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data

        email = validated_data.get("email")
        password = validated_data.get("password")

        existing_user = User.objects.filter(email=email).first()

        if existing_user is not None:

            if existing_user.is_active is False:
                existing_user.set_password(password)
                existing_user.save()
                user = existing_user
            else:

                return Response({
                    "status" : "error",
                    "message" : "Email address already exists",
                    "payload" : {}
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            username = AuthHelper.create_username(email=email)
            user = User.objects.create_user(
                username = username,
                is_active = False,
                **validated_data
            )
        

        serializer_data = self.serializer_class(user).data

        print("serializer_data" , serializer_data)

        context_data = {
            "host" : settings.FRONTEND_HOST,
            "uid" : urlsafe_base64_encode(force_bytes(user.id)),
            "token" : account_activation_token.make_token(user=user),
            "protocol" : "http"
        }

        print(context_data)

        return Response({
            "stauts" : "success",
            "message" : "Sent account varification link to your email address",
            "payload" : {
                **serializer_data,
                "tokens" : AuthHelper.get_tokens_for_user(user=user)
            }
        })


class ActiveAccountView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
        except Exception as e:
            user = None
        
        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()

            return Response({
                "status" : "success",
                "message" : "successfully verified",
                "payload" : {}
            }, status=status.HTTP_200_OK)
        
        else:
            return Response({
                "status" : "error",
                "message" : "invalid activiation link",
                "payload" : {}
            }, status=status.HTTP_403_FORBIDDEN)




class LoginView(APIView):

    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        request_data = request.data
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid() is False:

            return Response({
                'status' : 'error',
                'message' : validation_error_handler(serializer.errors),
                'payload' : {
                    "errors" : serializer.errors
                }
            })

        validated_data = serializer.validated_data

        username_or_email = validated_data["username_or_email"]
        password = validated_data["password"]

        user = (User.objects.filter(email=username_or_email).first() or User.objects.filter(username=username_or_email).first())

        if  user is not None:

            validated_password = check_password(
                password, user.password
            )

            if validated_password:
                if user.is_active is False:
                    return Response({
                        "status" : "error",
                        "message" : "user account is not active, please verify you email"
                    }, status=HTTP_403_FORBIDDEN)
                

                #example to pass context data to serializer , ignore context
                serializer_data = self.serializer_class(
                    user, context = { "request" : request }
                )

                return Response({
                    "status" : "success",
                    "message" : "login successfull",
                    "payload" : {
                        **serializer_data.data,
                        "token" : AuthHelper.get_tokens_for_user(user)
                    }
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    "status" : "error",
                    "message" : "invalid username and password",
                    "payload" : {}
                },status=status.HTTP_400_BAD_REQUEST)
            
        else:
            return Response({
                'status' : "error",
                "message" : "no user found",
                "payload" : {}
            },status=status.HTTP_404_NOT_FOUND)



class UserLogoutView(APIView):
    serializer_class = LogoutRequestSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request_data = request.data

        serializer = self.serializer_class(data=request_data)

        if serializer.is_valid() is False:
            return Response({
                "status" : "error",
                "message" : validation_error_handler(serializer.errors),
                "payload" : {
                    "errors" : serializer.errors
                }
            },status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data

        try:
            if validated_data.get('all'):
                for token in OutstandingToken.objects.filter(user=request.user):
                    _,_ = BlacklistedToken.objects.get_or_create(token=token)
                
                return Response({
                    "status" : "success",
                    "message" : "succesfully loggoed out from all the devices"
                }, status=status.HTTP_200_OK)
                

            refresh_token = validated_data.get('refresh')
            token = RefreshToken(token=refresh_token)
            token.blacklist()
            return Response({
                "status" : "success",
                "message": "succesfully logged out from  the devices"
            },status=status.HTTP_200_OK)


        except TokenError:
            return Response({
                "detail" : "token is blacklisted",
                "code" : "token_not valid"

            },status=status.HTTP_401_UNAUTHORIZED)


class CustomTokenRefreshView(TokenRefreshView):
    # serializer_class = CustomTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class ForgotPasswordView(APIView):
    serializer_class = ForgotPasswordSerializer
    throttle_classes = [forgotPasswordResetThrottle]

    def post(self, request, *args, **kwargs):
        request_data = request.data
        serializer = self.serializer_class(data=request_data)

        if serializer.is_valid() is False:
            return Response({
                "status" : "error",
                "message" : validation_error_handler(serializer.errors),
                "payload" : {
                    "errors" : serializer.errors
                }
            },status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email).first()

        uid, token = forogtoPasswordTokenGenerator(user)

        context_data = {
            "host" : settings.FRONTEND_HOST,
            "uid" :uid,
            "token" : token,
            "protocol" : "http"
        }

        print("forgot password reset link" , context_data)


        return Response({
            "status" : "success",
            "message" : "Password reset link is sent your email",
            "payload" : {}
        })


class ForgotPasswordReset(APIView):
    
    serializer_class = ForgotPasswordResetSerializer

    def post(self, request, uidb64, token):

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
        except Exception as e:
            user = None
        
        if user and default_token_generator.check_token(user, token):
            serializer = self.serializer_class(data=request.data, context={"user" : user})

            if serializer.is_valid() is False:
                return Response({
                    "status" : "Error",
                    "message" : validation_error_handler(serializer.errors),
                    "payload" : {
                        "errors" : serializer.errors
                    }
                }, status = status.HTTP_400_BAD_REQUEST)
            
            new_password = serializer.validated_data["new_password"]
            user.set_password(new_password)
            user.save()

            return Response({
                "status" : "success",
                "message" : "Successfully reset the password.",
                "payload" : {}
            }, status = status.HTTP_200_OK)
        
        return Response({
            "status" : "error",
            "message": "Password reset link is expired",
            "payload" : {}
        },status = status.HTTP_400_BAD_REQUEST)
        


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):

        return Response({
            "name" : "Nagaraj Murgod",
            "image" : "dummy.png",
            "address" : "earth"
        })