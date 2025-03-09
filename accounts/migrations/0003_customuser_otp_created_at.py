# Generated by Django 5.1.7 on 2025-03-08 23:20

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_customuser_email_otp_customuser_is_email_verified'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='otp_created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
