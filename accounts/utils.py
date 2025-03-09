import pyotp
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from axes.helpers import get_client_username
from logging import getLogger
from django.utils.timezone import now
from django.core.cache import cache
from axes.models import AccessAttempt


logger = getLogger(__name__)


User = get_user_model()


class OTP:

    @staticmethod
    def generate_otp(interval: int = 300) -> str:
        totp = pyotp.TOTP(
            pyotp.random_base32(), interval=interval
        )
        return totp.now()

    @classmethod
    def verify_otp(cls, otp: str, email: str) -> bool:
        if otp is None or email is None:
            return False
        
        otp_in_cache = cache.get(cls._otp_key_in_cache(email=email))
        if otp_in_cache is None:
            return False
        
        if otp_in_cache != otp:
            return False

        # Delete the OTP from cache after successful verification
        cache.delete(cls._otp_key_in_cache(email=email))

        return True

    @classmethod
    def _otp_key_in_cache(cls, email: str) -> str:
        return f"otp:{email}"

    @classmethod
    def _store_otp_in_cache(cls, email: str, otp: str, timeout: int):
        cache.set(cls._otp_key_in_cache(email=email), otp, timeout=timeout)

    @classmethod
    def send_and_cache_otp(cls, email: str, otp: str):
        cls._store_otp_in_cache(email=email, otp=otp, timeout=settings.OTP_EXPIRY)
        send_mail(
            "One-time Password (OTP) Confirmation Email",
            f"Dear User,\n\nYour One-time Password (OTP) is {otp}.\nPlease enter this password to proceed with your login process.\n\nThank you.",
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False
            )


def send_warning_email(request, credentials, *args, **kwargs):
    username = get_client_username(request, credentials)
    user = User.objects.filter(email=username).first()
    
    if user:
        send_mail(
            "Warning: Multiple Unsuccessful Login Attempts",
            "Dear User,\n\nThere have been multiple unsuccessful login attempts on your account. "
            "If this wasn't you, please secure your account immediately.\n\nThank you.",
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )
    else:
        logger.error(f"User with username {username} not found!")


class SuspiciousActivity:
    # More than x attempts in Time Window hour => suspicious
    THRESHOLD_ATTEMPTS = 10
    TIME_WINDOW = timedelta(hours=1)  # 1-hour window

    @classmethod
    def send_suspicious_activity_alert(cls, email, ip_address):
        """
        Send an alert email if suspicious login activity is detected.
        """
        subject = "⚠️ Suspicious Login Activity Detected"
        message = f"""
        We detected multiple failed login attempts from your account or IP address.

        Details:
        - Email: {email if email else "Unknown"}
        - IP Address: {ip_address if ip_address else "Unknown"}
        - Time: {now().strftime("%Y-%m-%d %H:%M:%S")}

        If this wasn't you, please reset your password immediately.

        Regards,
        Security Team
        """
        
        recipient = email if email else settings.ADMIN_EMAIL  # Default to admin if no email
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient])

    @classmethod
    def check_suspicious_activity(cls, email=None, ip_address=None):
        """
        Check if there are more than 10 failed login attempts within the last 1 hour
        from the same IP or for the same email.
        """
        one_hour_ago = now() - cls.TIME_WINDOW

        # Query failed attempts in the last 1 hour
        suspicious_attempts = AccessAttempt.objects.filter(attempt_time__gte=one_hour_ago)

        if email:
            suspicious_attempts = suspicious_attempts.filter(username=email)

        if ip_address:
            suspicious_attempts = suspicious_attempts.filter(ip_address=ip_address)

        if suspicious_attempts.count() > cls.THRESHOLD_ATTEMPTS:
            cls.send_suspicious_activity_alert(email, ip_address)