from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework import status, permissions
from django.contrib.auth import get_user_model
from django.core.cache import cache
from drf_yasg.utils import swagger_auto_schema

from accounts.serializers import UserSerializer, LoginSerializer, VerifyOTPSerializer


User = get_user_model()


class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)  # Get JWT token
        user = User.objects.get(email=request.data["email"])  # Fetch user

        # Store user_id -> phone_number in Redis for `notif_service`
        cache.set(
            f"email:{user.id}", user.email, timeout=86400
        )  # Expire in 1 day

        return response


class VerifyOTPView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VerifyOTPSerializer

    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp_provided = serializer.validated_data["otp"]
        email = request.user.email

        # Fetch OTP from Redis
        # cache.set(f"otp:{phone_number}", "12344", timeout=300)
        stored_otp = cache.get(f"otp:{email}")

        if stored_otp is None:
            return Response(
                {"error": "OTP expired or not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(stored_otp) == str(otp_provided):
            cache.delete(
                f"otp:{email}"
            )  # Delete OTP after successful verification
            return Response(
                {"message": "OTP verified successfully"}, status=status.HTTP_200_OK
            )

        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
