"""Adversarial cases for the defaults rule.

Modelled on the PyYAML fix, which changed load(stream, Loader=Loader) to
load(stream, Loader=None). The call to Loader is present in both versions, so
these cases exercise what a calls rule cannot see.
"""

from yaml import Loader


def vulnerable_default(stream, Loader=Loader):
    return Loader(stream).get_single_data()


def fixed_default(stream, Loader=None):
    if Loader is None:
        Loader = SafeLoader
    return Loader(stream).get_single_data()


def required_argument(stream, Loader):
    """No default at all. PyYAML 6.0 made Loader required.

    A rule asking for Loader=Loader must not match here: the dangerous default
    is gone, and matching would report a fixed version as vulnerable.
    """
    return Loader(stream).get_single_data()


def different_parameter(stream, Dumper=Loader):
    """Same default value, different parameter name."""
    return Dumper(stream)


def different_value(stream, Loader=SafeLoader):
    """Same parameter name, different default."""
    return Loader(stream)


def value_in_comment(stream, Loader=None):
    # Loader=Loader appears here and must not count
    return Loader(stream)


def value_in_docstring(stream, Loader=None):
    """Signature was once Loader=Loader, which must not count."""
    return Loader(stream)


def value_in_string(stream, Loader=None):
    msg = "the old signature was Loader=Loader"
    return msg


def outer_with_nested_default(stream, Loader=None):
    """The nested function carries the dangerous default, not this one."""

    def inner(data, Loader=Loader):
        return Loader(data)

    return inner(stream)


def nested_is_clean(stream, Loader=Loader):
    """This one carries it; the nested function does not."""

    def inner(data, Loader=None):
        return data

    return inner(stream)


def keyword_only_default(stream, *, Loader=Loader):
    """Keyword-only parameters are still default_parameter nodes."""
    return Loader(stream)


def with_annotation(stream: str, Loader: type = Loader):
    """An annotated parameter with a default."""
    return Loader(stream)


async def async_default(stream, Loader=Loader):
    return Loader(stream)


@staticmethod
def decorated_default(stream, Loader=Loader):
    return Loader(stream)


def dotted_default(stream, Loader=yaml.Loader):
    """A dotted default value, matched exactly."""
    return Loader(stream)


def splat_params(stream, Loader=Loader, *args, **kwargs):
    return Loader(stream)


class Alpha:
    def parse(self, stream, Loader=Loader):
        return Loader(stream)


class Beta:
    def parse(self, stream, Loader=None):
        return Loader(stream)
