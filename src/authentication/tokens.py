from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
import six
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self,user,timestamp):
        return (
            six.text_type(user.pk)+six.text_type(timestamp)+six.text_type(user.is_active)
        )


def forogtoPasswordTokenGenerator(user):
    token = default_token_generator.make_token(user=user)
    uid = urlsafe_base64_encode(force_bytes(user.id))
    return uid, token

    
account_activation_token = TokenGenerator()


