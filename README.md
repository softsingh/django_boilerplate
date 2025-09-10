# Django Boilerplate
This is the Boilerplate for Django based projects

## How to run
Create python virtual environment and install dependencies
<pre lang="markdown">
$ cd django_boilerplate
$ py -m venv venv
$ venv\Scripts\activate
$ pip install -r requirements.txt
</pre>

Rename `.env_example` to `.env` and modify database and email settings inside it
<pre lang="markdown">
$ ren .env_example .env
</pre>

Create database and run migrations
<pre lang="markdown">
$ py manage.py migrate
</pre>

Create Superuser
<pre lang="markdown">
$ py manage.py createsuperuser
</pre>

Run Server
<pre lang="markdown">
$ py manage.py runserver
</pre>

## Testing
Pytest is used for testing the project

Test entire project
<pre lang="markdown">
$ pytest
</pre>

Test with key (all tests that contain the text)
<pre lang="markdown">
$ pytest -k "test_user_login_view"
</pre>

All tests inside specific file
<pre lang="markdown">
$ pytest user/tests/test_models.py
</pre>

Save coverage report as html
<pre lang="markdown">
$ pytest --cov=. --cov-report=html
</pre>