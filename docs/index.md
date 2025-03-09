# Documentation

This project uses **Django 5.1** as the along with **Redis** and preferebly **Postgresql** as the database. Redis is used as the cache backend for django. It allows **django-axes** to cache users' login attempts and also cache the otp code for the email verification so that the database hit will reduce considerably.

The main responsibility of managing login attempts, history and other policies is implemented using **django-axes**. This library is quiet suitable for such cases and with some customization and configuration it performs as expected for this code challenge scenario.

Please make sure you have set appropriate EMAIL backend (I have tested with google smtp and it worked quiet well) before running the project.

## Setup

1. clone the project: `git clone https://github.com/Hassan-Ahmadi/sanaap.git` 
2. create a `venv` and install packages using `pip3 install -r requirements.txt`
3. create a `.env` file and pass the required env params like db, ...
4. run the `python manage.py migrate`
5. run the project using `python manage.py runserver`

## Containerization

The docker-compose and DockerFile are mostly configured correctly but not tested.
