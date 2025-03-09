from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework import status, permissions
from django.contrib.auth import get_user_model, login
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics
from rest_framework.permissions import IsAdminUser
from axes.models import AccessAttempt, AccessLog
from axes.helpers import get_client_ip_address
from axes.utils import reset
from django.conf import settings


from accounts.serializers import AccessAttemptSerializer, AccessLogSerializer
from accounts.serializers import (
    UserSerializer,
    LoginSerializer,
    VerifyOTPSerializer,
    OTPSerializer,
)

from .utils import OTP
from axes.decorators import axes_dispatch


User = get_user_model()


class SignupView(generics.CreateAPIView):
    """
    API view to handle user signup.
    """

    permission_classes = [permissions.AllowAny]
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user_email = serializer.validated_data["email"]
        otp = OTP.generate_otp(interval=settings.OTP_EXPIRY)
        # serializer.save(email_otp=otp)
        OTP.send_and_cache_otp(email=user_email, otp=otp)

        return super().perform_create(serializer)
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                "message": "User created successfully. An OTP has been sent to your email.",
                "user": serializer.data,
            },
            status=status.HTTP_201_CREATED,
            headers=headers,
        )


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get("email")
        ip = get_client_ip_address(request)
        
        serializer = self.get_serializer(data=request.data, context={'request': request})
        # serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data["user"]
        
        login(request=request, user=user, backend='django.contrib.auth.backends.ModelBackend')
        
        # Reset the failed login attempts on successful login
        reset(username=username, ip=ip)
        
        return Response(
            {
                "message": "Login successful",
                "access_token": serializer.validated_data["access_token"],
                "refresh_token": serializer.validated_data["refresh_token"],
            },
            status=status.HTTP_200_OK,
        )


class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = VerifyOTPSerializer

    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp_provided = serializer.validated_data["otp"]
        user = User.objects.filter(email=email).first()

        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        if not OTP.verify_otp(otp=otp_provided, email=email):
            return Response(
                {"error": "OTP not valid or expired!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_email_verified = True
        user.is_active = True
        user.save()

        return Response(
            {"message": "OTP verified successfully"}, status=status.HTTP_200_OK
        )


class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = OTPSerializer

    @swagger_auto_schema(request_body=OTPSerializer)
    def post(self, request):
        email = request.data.get("email")
        user = generics.get_object_or_404(User, email=email)
        new_otp = OTP.generate_otp(interval=settings.OTP_EXPIRY)
        user.save()
        OTP.send_and_cache_otp(email=email, otp=new_otp)
        return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)


class AdminAccessAttemptView(generics.ListAPIView):
    """
    API endpoint to retrieve failed login attempts for system administrators.
    """

    queryset = AccessAttempt.objects.all().order_by("-attempt_time")
    serializer_class = AccessAttemptSerializer
    permission_classes = [IsAdminUser]


class AdminAccessLogtView(generics.ListAPIView):
    """
    API endpoint to retrieve failed login attempts for system administrators.
    """

    queryset = AccessLog.objects.all().order_by("-attempt_time")
    serializer_class = AccessLogSerializer
    permission_classes = [IsAdminUser]

