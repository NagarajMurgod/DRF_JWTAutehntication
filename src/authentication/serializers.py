
from rest_framework import serializers
from authentication.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator

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
            