from django.contrib import admin
from .models import CustomUser

# admin.site.register(CustomUser)

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    
    list_display = (
        "email",
        "first_name",
        "last_name",
        "last_login",
        "is_active",
        "is_staff",
        "is_superuser"
    )
