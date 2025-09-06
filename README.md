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
