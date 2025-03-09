from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from axes.models import AccessAttempt, AccessLog
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy as _


User = get_user_model()


class AccessAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessAttempt
        fields = "__all__"


class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        # add some monitoring event here, later
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        request = self.context.get("request")
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            raise AuthenticationFailed(_("Both email and password are required."))

        user = authenticate(request=request, email=email, password=password)

        if not user:
            raise AuthenticationFailed(_("Invalid email or password."))

        if not user.is_active:
            raise AuthenticationFailed(_("This account is inactive."))
        
        if not user.is_email_verified:
            raise AuthenticationFailed(_("Email is not verified. Please verify your email."))

        # Update last login
        update_last_login(None, user)

        # Generate JWT tokens (if using SimpleJWT)
        refresh = RefreshToken.for_user(user)

        return {
            "user": user,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
        }


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True, max_length=6, min_length=6)
    email = serializers.EmailField(write_only=True)

    def validate_otp(self, value):
        """Ensure the OTP is numeric."""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value


class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
