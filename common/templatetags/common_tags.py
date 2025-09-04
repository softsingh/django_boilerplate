from django import template

register = template.Library()


@register.filter
def replace(value, args):
    """Find and replace text"""

    parts = args.split(",", 1)
    if len(parts) != 2:
        return value
    old, new = parts
    return value.replace(old, new)


@register.filter
def class_name(value):
    """Returns the class name of a given value."""

    return value.__class__.__name__


@register.filter
def initials(name):
    """
    Extract initials from a name.
    Examples:
    - "First Last" -> "FL"
    - "First Middle Last" -> "FL"
    - "First" -> "F"
    """
    if not name:
        return ""

    parts = [w for w in str(name).split() if w]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0][0].upper()
    return (parts[0][0] + parts[-1][0]).upper()


@register.filter
def add_error_class(field, errors):
    """
    Adds 'invalid' CSS class to the field if it has errors,
    while keeping existing classes intact.
    """
    if errors:
        # Get existing classes from the widget, if any
        existing_classes = field.field.widget.attrs.get("class", "")
        # Append the 'is-invalid' class
        updated_classes = f"{existing_classes} invalid".strip()
        # Render the field with the updated classes
        return field.as_widget(attrs={"class": updated_classes})
    return field
