from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class forgotPasswordResetThrottle(AnonRateThrottle):
    rate = "10/minutes"