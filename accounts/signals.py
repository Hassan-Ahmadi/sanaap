from django.dispatch import receiver
from axes.signals import user_login_failed, user_locked_out
from accounts.utils import SuspiciousActivity
from rest_framework.exceptions import PermissionDenied


@receiver(user_login_failed)
def detect_suspicious_activity(sender, credentials, request, **kwargs):
    """
    Detects suspicious activity when more than THRESHOLD_ATTEMPTS failed login attempts occur
    from the same IP or for the same email within TIME_WINDOW.
    """
    email = credentials.get("email")
    ip_address = request.META.get("REMOTE_ADDR") if request else None

    SuspiciousActivity.check_suspicious_activity(email=email, ip_address=ip_address)

@receiver(user_locked_out)
def raise_permission_denied(*args, **kwargs):
    raise PermissionDenied("Too many failed login attempts")