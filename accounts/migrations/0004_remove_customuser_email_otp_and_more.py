# Generated by Django 5.1.7 on 2025-03-09 02:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_customuser_otp_created_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='email_otp',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='otp_created_at',
        ),
    ]
