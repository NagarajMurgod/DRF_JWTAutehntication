import shortuuid
from authentication.models import User
from rest_framework_simplejwt.tokens import RefreshToken

class AuthHelper:
    @staticmethod
    def create_username(email):
        try:
            total_retries = 5
            email_split = email.rsplit(
                '@', 1
            )
            email_part = email_split[0][0:20]
            clean_email_part = "".join(char for char in email_part if char.isalnum())

            for i in range(total_retries):
                uuid = shortuuid.uuid()
                username = f"{clean_email_part}_{uuid}".lower()
                user = User.objects.filter(username=username)
                if not user.exists():
                    return username
                
            raise Exception("Max retries done for creating a new username")
        except Exception as e:
            raise Exception("Error while generating a new usename") from e

    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user=user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }


def validation_error_handler(data):
    key = list(data.keys())[0]
    value = data[key]
    print(value, key)
    if type(value) == list:
        message = f"{value[0]}"

    else:
        message = f"{value}"
    
    return message