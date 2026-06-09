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

## How to use Advanced Query Modal
The advance query Modal has been implemented in the user app.
The following files must be present before we begin.
1. "common\templates\common\includes\_advanced_query_modal.html"
2. "common\templates\common\includes\_advanced_query_script.html"
3. "common\advanced_query.py"

Sample utils.py :
<pre lang="markdown">
.
.
from common.choices import Gender
from common.advanced_query import AdvancedQueryService

USER_ADVANCED_QUERY_CONFIG = {
    "full_name": {
        "label": "Full Name",
        "orm": "profile__full_name",
        "type": "str",
        "ui_type": "text",
        "operators": {"eq", "contains", "startswith", "endswith", "in"},
    },
    "phone_number": {
        "label": "Phone Number",
        "orm": "profile__phone_number",
        "type": "str",
        "ui_type": "text",
        "operators": {"eq", "contains", "startswith", "endswith", "in"},
    },
    "gender_1": {
        "label": "Gender",
        "orm": "profile__gender",
        "type": "choice",
        "ui_type": "choice",
        "operators": {"eq", "in"},
        "choices": {"Male", "Female", "Other"},
    },
    "gender_2": {
        "label": "Gender",
        "orm": "profile__gender",
        "type": "choice",
        "ui_type": "choice",
        "operators": {"eq", "in"},
        "choices": {value for value, _ in Gender.choices},
    },
    "date": {
        "label": "Date",
        "orm": "sample_date",
        "type": "date",
        "ui_type": "date",
        "operators": {"eq", "gt", "gte", "lt", "lte", "between"},
    },
    "active": {
        "label": "Active",
        "orm": "is_active",
        "type": "bool",
        "operators": ["eq"],
    },
    "remarks": {
        "label": "Remarks",
        "orm": "profile__remarks",
        "type": "str",
        "ui_type": "text",
        "operators": {"eq", "contains", "startswith", "endswith"},
    },
}

user_advanced_query_service = AdvancedQueryService(USER_ADVANCED_QUERY_CONFIG)
.
.
def get_filtered_users(queryset, status="", role="", query=""):

    # Status filter
    status_map = {"active": True, "disabled": False}
    if status in status_map:
        queryset = queryset.filter(is_active=status_map[status])

    # Role filter
    role_map = {"admin": True, "user": False}
    if role in role_map:
        queryset = queryset.filter(is_superuser=role_map[role])

    if query:
        query = query.strip()

        if query.startswith("query:"):
            queryset = user_advanced_query_service.apply(queryset, query)
        else:
            queryset = queryset.filter(
                Q(username__icontains=query)
                | Q(profile__full_name__icontains=query)
                | Q(email__icontains=query)
                | Q(profile__phone_number__icontains=query)
                | Q(profile__remarks__icontains=query)
            ).distinct()

    return queryset
.
.
</pre>

Sample views.py
<pre lang="markdown">
.
.
from common.choices import Gender
from common.advanced_query import build_advanced_query_context
.

class UserListView(
    LoginRequiredMixin,
    MyPermissionRequiredMixin,
    ListView,
):
    """Displays list of users based on filters applied"""

    model = CustomUser
    template_name = "user/list.html"
    context_object_name = "users"
    permission_required = "user.can_view_others_profile"
    permission_denied_message = "You do not have permission to view this page"
    paginate_by = 10

    def get_paginate_by(self, queryset):
        page_size = self.request.GET.get("page_size")
        if page_size and page_size.isdigit():
            return int(page_size)
        return self.paginate_by

    def get_queryset(self):
        status = self.request.GET.get("status", "")
        role = self.request.GET.get("role", "")
        query = self.request.GET.get("q", "")
        queryset = (
            CustomUser.objects.select_related("profile")
            .prefetch_related("groups", "user_permissions")
            .order_by("profile__full_name")
        )
        queryset = utils.get_filtered_users(
            queryset, status=status, role=role, query=query
        )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["current_page_size"] = self.get_paginate_by(self.get_queryset())
        context["page_size_options"] = [5, 10, 20, 50, 100]
        context["status_options"] = {
            "< Status >": "",
            "Active": "active",
            "Disabled": "disabled",
        }
        context["role_options"] = {
            "< Role >": "",
            "Admin": "admin",
            "User": "user",
        }
        context.update(
            build_advanced_query_context(
                config=utils.USER_ADVANCED_QUERY_CONFIG,
                choice_values={
                    "gender": [
                        {"value": value, "label": label}
                        for value, label in Gender.choices
                    ]
                },
            )
        )
        return context
</pre>

Sample list.html
```html
.
.
{% block content %}
   <div class="col-12 col-sm-6">
      <form method="get" id="formSearchFromUsers">
         <div class="d-flex align-items-center gap-1">
            <div class="search-field w-100">
               <input type="search"
                      placeholder="Search from Users"
                      class="form-control search-field-input"
                      name="q"
                      id="id_q"
                      value="{{ request.GET.q|default:'' }}">
               <i class="bx bx-x bx-sm search-field-clear" data-clear-submit="true"></i>
            </div>
            <button class="btn btn-outline-secondary"
                    type="button"
                    data-toggle="modal"
                    data-target="modalUserAdvancedQuery"
                    data-aq-open="modalUserAdvancedQuery"
                    title="Advanced Search">
               <div class="d-flex align-items-center">
                  <i class="bx bx-slider fs-4"></i>
               </div>
            </button>
         </div>
         <input type="hidden" name="page_size" value="{{ current_page_size }}">
         <input type="hidden"
                name="status"
                value="{{ request.GET.status|default:'' }}">
         <input type="hidden" name="role" value="{{ request.GET.role|default:'' }}">
      </form>
   </div>
   {% include "common/includes/_advanced_query_modal.html" with modal_id="modalUserAdvancedQuery" modal_title="User Advanced Query" %}
   {% include "common/includes/_advanced_query_script.html" with modal_id="modalUserAdvancedQuery" query_input_selector="#id_q" aq_filter_options_id="user_advanced_query_filter_options" aq_operator_options_id="user_advanced_query_operator_options" aq_choice_values_id="user_advanced_query_choice_values" %}
{% endblock content %}
```

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