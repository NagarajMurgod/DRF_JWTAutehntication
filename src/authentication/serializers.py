
from rest_framework import serializers
from authentication.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator
from rest_framework_simplejwt.serializers import (
    TokenRefreshSerializer
)
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "email",
            "password"
        ]

        extra_kwargs = {
            "password" : {"write_only" : True},
            "email" : {
                "validators" : [EmailValidator]
            }
        }

    def validate_password(self, value):
        validate_password(value)
        return value
    
    def validate_email(self, value):
        return value.lower()


class UserLoginSerializer(serializers.ModelSerializer):
    username_or_email = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = (
            "username_or_email",
            "email",
            "password",
            "username",
            "first_name",
            "last_name",
            "date_joined",
            "is_active",
            "is_superuser"
        )

        read_only_fields = [
            "email",
            "username",
            "first_name",
            "last_name",
            "date_joined",
            "is_active",
            "is_superuser"
        ]


        extra_kwargs = {
            "password" : { "write_only" : True}
        }


    def validate_username_or_email(self,value):
        return value.lower()


class LogoutRequestSerializer(serializers.Serializer):
    all = serializers.BooleanField(required=False)
    refresh = serializers.CharField(required=False)

    def validate(self, attrs):
        all = attrs.get('all')
        refresh = attrs.get('refresh')

        if not all and not refresh:
            raise serializers.ValidationError({
                "refresh" : "if logout from all device parameter with value true else refresh token"
            })

        return super().validate(attrs)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value).first()

        if user is None or not user.is_active :
            raise serializers.ValidationError("This Email is not registered")

        return value


class ForgotPasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        new_password = attrs["new_password"]
        confirm_password = attrs["confirm_password"]

        if new_password != confirm_password:
            raise serializers.ValidationError("Password must match")
        
        if self.context.get("user").check_password(new_password):
            raise serializers.ValidationError("New password is same as old password")
        
        validate_password(new_password)
        return super().validate(attrs)


        

class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs["refresh"])
            data = {"access": str(refresh.access_token)}
            if settings.SIMPLE_JWT["ROTATE_REFRESH_TOKENS"]:
                payload = refresh.payload
                id = payload["user_id"]
                user = User.objects.get(id=id)
                if not settings.ALLOW_NEW_REFRESH_TOKENS_FOR_UNVERIFIED_USERS:
                    if user.is_active == False:
                        raise TokenError({"details": "User is inactive", "code": "user_inactive"})
                    
                if settings.SIMPLE_JWT["BLACKLIST_AFTER_ROTATION"]:
                    try:
                        refresh.blacklist()
                    except AttributeError:
                        pass

                refresh.set_jti()
                refresh.set_exp()

                if settings.SIMPLE_JWT["BLACKLIST_AFTER_ROTATION"]:
                    OutstandingToken.objects.create(
                        user=user,
                        jti=payload[settings.SIMPLE_JWT["JTI_CLAIM"]],
                        token=str(refresh),
                        created_at=refresh.current_time,
                        expires_at=datetime_from_epoch(payload["exp"]),
                    )
                
                data["refresh"] = str(refresh)
            return data
        except TokenError as e:
            raise

        except serializers.ValidationError:
            raise

        except Exception:
            raise
    