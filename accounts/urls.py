from django.urls import path
from .views import SignupView, LoginView, VerifyOTPView


app_name = "accounts"


urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
]