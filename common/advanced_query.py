from datetime import datetime

from django.core.exceptions import ValidationError

ADVANCED_QUERY_PREFIX = "query:"


class AdvancedQueryService:
    def __init__(self, config):
        self.config = config or {}

    def parse(self, query):
        if not query:
            return None

        query = query.strip()
        if not query.startswith(ADVANCED_QUERY_PREFIX):
            return None

        body = query[len(ADVANCED_QUERY_PREFIX) :].strip()
        if not body:
            return []

        clauses = []
        raw_clauses = [item.strip() for item in body.split(";") if item.strip()]

        for raw_clause in raw_clauses:
            parts = raw_clause.split(":", 2)
            if len(parts) != 3:
                raise ValidationError(f"Invalid advanced query clause: {raw_clause}")

            field_name, operator, raw_value = [part.strip() for part in parts]

            if field_name not in self.config:
                raise ValidationError(f"Unsupported advanced query field: {field_name}")

            meta = self.config[field_name]
            allowed_operators = set(meta.get("operators", []))

            if operator not in allowed_operators:
                raise ValidationError(
                    f"Unsupported operator '{operator}' for field '{field_name}'."
                )

            if not raw_value:
                raise ValidationError(f"Value missing for field '{field_name}'.")

            parsed_value = self._parse_value(
                meta=meta,
                operator=operator,
                raw_value=raw_value,
            )

            clauses.append(
                {
                    "field": field_name,
                    "operator": operator,
                    "value": parsed_value,
                    "raw_value": raw_value,
                    "orm": meta["orm"],
                }
            )

        return clauses

    def apply(self, queryset, query):
        clauses = self.parse(query)
        if clauses is None:
            return queryset

        for clause in clauses:
            orm = clause["orm"]
            operator = clause["operator"]
            value = clause["value"]

            if operator == "eq":
                queryset = queryset.filter(**{orm: value})
            elif operator == "contains":
                queryset = queryset.filter(**{f"{orm}__icontains": value})
            elif operator == "startswith":
                queryset = queryset.filter(**{f"{orm}__istartswith": value})
            elif operator == "endswith":
                queryset = queryset.filter(**{f"{orm}__iendswith": value})
            elif operator == "gt":
                queryset = queryset.filter(**{f"{orm}__gt": value})
            elif operator == "gte":
                queryset = queryset.filter(**{f"{orm}__gte": value})
            elif operator == "lt":
                queryset = queryset.filter(**{f"{orm}__lt": value})
            elif operator == "lte":
                queryset = queryset.filter(**{f"{orm}__lte": value})
            elif operator == "between":
                queryset = queryset.filter(**{f"{orm}__range": value})
            elif operator == "in":
                queryset = queryset.filter(**{f"{orm}__in": value})
            elif operator == "isnull":
                queryset = queryset.filter(**{f"{orm}__isnull": value})
            else:
                raise ValidationError(f"Unsupported operator: {operator}")

        return queryset.distinct()

    def _parse_value(self, meta, operator, raw_value):
        value_type = meta.get("type", "str")
        parser = self._get_parser(value_type)

        if value_type == "choice":
            return self._parse_choice(meta, operator, raw_value)

        if operator == "between":
            values = self._parse_list(raw_value, parser)
            if len(values) != 2:
                raise ValidationError(
                    f"Operator 'between' for '{meta.get('label', meta['orm'])}' requires exactly 2 values."
                )
            return values

        if operator == "in":
            return self._parse_list(raw_value, parser)

        if operator == "isnull":
            val = raw_value.strip().lower()
            if val not in {"true", "false", "1", "0"}:
                raise ValidationError("isnull supports only true/false.")
            return val in {"true", "1"}

        return parser(raw_value)

    def _parse_choice(self, meta, operator, raw_value):
        choices = set(meta.get("choices", []))

        if operator == "in":
            values = self._parse_list(raw_value, self._parse_str)
            invalid_values = [v for v in values if v not in choices]
            if invalid_values:
                raise ValidationError(
                    f"Invalid value(s) for '{meta.get('label', meta['orm'])}': {', '.join(invalid_values)}"
                )
            return values

        value = self._parse_str(raw_value)
        if value not in choices:
            raise ValidationError(
                f"Invalid value for '{meta.get('label', meta['orm'])}': {value}"
            )
        return value

    def _get_parser(self, value_type):
        if value_type == "int":
            return self._parse_int
        if value_type == "date":
            return self._parse_date
        if value_type == "bool":
            return self._parse_bool
        return self._parse_str

    def _parse_list(self, raw_value, parser):
        values = [item.strip() for item in raw_value.split(",")]
        values = [item for item in values if item]
        if not values:
            raise ValidationError("List value cannot be empty.")
        return [parser(item) for item in values]

    def _parse_int(self, value):
        return int(value.strip())

    def _parse_str(self, value):
        return value.strip()

    def _parse_date(self, value):
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()

    def _parse_bool(self, value):
        val = value.strip().lower()
        if val in {"true", "1", "yes"}:
            return True
        if val in {"false", "0", "no"}:
            return False
        raise ValidationError(f"Invalid boolean value: {value}")


DEFAULT_ADVANCED_QUERY_OPERATOR_OPTIONS = {
    "number": [
        {"value": "eq", "label": "Equal"},
        {"value": "gt", "label": "Greater Than"},
        {"value": "gte", "label": "Greater Than or Equal"},
        {"value": "lt", "label": "Less Than"},
        {"value": "lte", "label": "Less Than or Equal"},
        {"value": "between", "label": "From To"},
        {"value": "in", "label": "From List"},
    ],
    "text": [
        {"value": "eq", "label": "Equal"},
        {"value": "contains", "label": "Contains"},
        {"value": "startswith", "label": "Starts With"},
        {"value": "endswith", "label": "Ends With"},
        {"value": "in", "label": "From List"},
    ],
    "choice": [
        {"value": "eq", "label": "Equal"},
        {"value": "in", "label": "From List"},
    ],
    "date": [
        {"value": "eq", "label": "Equal"},
        {"value": "gt", "label": "Greater Than"},
        {"value": "gte", "label": "Greater Than or Equal"},
        {"value": "lt", "label": "Less Than"},
        {"value": "lte", "label": "Less Than or Equal"},
        {"value": "between", "label": "From - To"},
    ],
    "boolean": [
        {"value": "eq", "label": "Equal"},
    ],
}


def build_advanced_query_context(config, choice_values=None):
    filter_options = []
    choices = choice_values or {}

    for field_name, meta in config.items():
        field_type = meta.get("ui_type") or meta.get("type", "text")
        if field_type == "str":
            field_type = "text"
        if field_type == "int":
            field_type = "number"
        if field_type == "bool":
            field_type = "boolean"

        filter_options.append(
            {
                "value": field_name,
                "label": meta.get("label", field_name.replace("_", " ").title()),
                "type": field_type,
            }
        )

    return {
        "advanced_query_filter_options": filter_options,
        "advanced_query_operator_options": DEFAULT_ADVANCED_QUERY_OPERATOR_OPTIONS,
        "advanced_query_choice_values": choices,
    }
