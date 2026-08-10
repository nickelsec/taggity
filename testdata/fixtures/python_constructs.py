import os
from os import system as run_it


def clean_no_eval(data):
    """Nothing dangerous here at all."""
    return data.strip()


def comment_only(data):
    # this comment mentions eval( and must NOT count
    return int(data)


def docstring_only(data):
    """Docstring mentioning eval( which must NOT count."""
    return int(data)


def string_literal_only(data):
    msg = "call eval( on this"
    return msg


def real_call(data):
    return eval(data)


def outer_with_nested(data):
    def nested_evil():
        return eval(data)
    return nested_evil


def nested_is_clean(data):
    def helper():
        return data.strip()
    return eval(helper())


async def async_real_call(data):
    return eval(data)


@staticmethod
def decorated_real_call(data):
    return eval(data)


@some.decorator(
    arg1="x",
    arg2="y",
)
def multiline_decorated(data):
    return eval(data)


def lambda_holder(data):
    f = lambda x: eval(x)
    return f(data)


def continuation(data):
    result = eval( \
        data)
    return result


class Alpha:
    def parse_untrusted(self, data):
        return eval(data)


class Beta:
    def parse_untrusted(self, data):
        return int(data)


def shadowed_name(data):
    eval = safe_thing
    return eval(data)


def attribute_call(data):
    return os.eval(data)


class Gamma:
    def dup_method(self, data):
        return eval(data)


class Delta:
    def dup_method(self, data):
        return int(data)


def dotted_sink(data):
    return pickle.loads(data)


def dotted_other(data):
    return json.loads(data)


def aliased_import_call(data):
    return loads(data)
