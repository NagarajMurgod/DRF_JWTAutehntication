from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .serializers import CreateUserSerializer
from rest_framework.response import Response
from .helpers import validation_error_handler
from rest_framework import status

User = get_user_mode()

class SignupApiView(APIView):

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
        