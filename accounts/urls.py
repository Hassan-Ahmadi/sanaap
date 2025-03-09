from django.urls import path
from django.urls import path
from accounts.views import AdminAccessAttemptView, AdminAccessLogtView
from .views import SignupView, LoginView, VerifyOTPView, ResendOTPView


app_name = "accounts"


urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("resend-otp/", ResendOTPView.as_view(), name="resend-otp"),
    path("access-attempts/", AdminAccessAttemptView.as_view(), name="access-attempts"),
    path("access-logs/", AdminAccessLogtView.as_view(), name="access-logs"),
]
