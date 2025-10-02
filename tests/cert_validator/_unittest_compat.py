import re
import unittest

str_cls = str


_non_local = {"patched": False}


def patch():
    return

    if _non_local["patched"]:
        return

    unittest.TestCase.assertRegex = unittest.TestCase.assertRegexpMatches
    unittest.TestCase.assertRaisesRegex = unittest.TestCase.assertRaisesRegexp
    _non_local["patched"] = True


def _safe_repr(obj):
    try:
        return repr(obj)
    except Exception:
        return object.__repr__(obj)


def _format_message(msg, standard_msg):
    return msg or standard_msg


def _assert_greater_equal(self, a, b, msg=None):
    if not a >= b:
        standard_msg = f"{_safe_repr(a)} not greater than or equal to {_safe_repr(b)}"
        self.fail(_format_message(msg, standard_msg))


def _assert_less(self, a, b, msg=None):
    if not a < b:
        standard_msg = f"{_safe_repr(a)} not less than {_safe_repr(b)}"
        self.fail(_format_message(msg, standard_msg))


def _assert_less_equal(self, a, b, msg=None):
    if not a <= b:
        standard_msg = f"{_safe_repr(a)} not less than or equal to {_safe_repr(b)}"
        self.fail(_format_message(msg, standard_msg))


def _assert_is_instance(self, obj, cls, msg=None):
    if not isinstance(obj, cls):
        if not msg:
            msg = f"{obj} is not an instance of {cls!r}"
        self.fail(msg)


def _assert_in(self, member, container, msg=None):
    if member not in container:
        standard_msg = f"{_safe_repr(member)} not found in {_safe_repr(container)}"
        self.fail(_format_message(msg, standard_msg))


def _assert_not_in(self, member, container, msg=None):
    if member in container:
        standard_msg = f"{_safe_repr(member)} found in {_safe_repr(container)}"
        self.fail(_format_message(msg, standard_msg))


def _assert_regex(self, text, expected_regexp, msg=None):
    """Fail the test unless the text matches the regular expression."""
    if isinstance(expected_regexp, str_cls):
        expected_regexp = re.compile(expected_regexp)
    if not expected_regexp.search(text):
        msg = msg or "Regexp didn't match"
        msg = f"{msg}: {expected_regexp.pattern!r} not found in {text!r}"
        self.fail(msg)


def _assert_raises(self, excClass, callableObj=None, *args, **kwargs):
    context = _AssertRaisesContext(excClass, self)
    if callableObj is None:
        return context
    with context:
        callableObj(*args, **kwargs)
        return None


def _assert_raises_regex(
    self, expected_exception, expected_regexp, callable_obj=None, *args, **kwargs
):
    if expected_regexp is not None:
        expected_regexp = re.compile(expected_regexp)
    context = _AssertRaisesContext(expected_exception, self, expected_regexp)
    if callable_obj is None:
        return context
    with context:
        callable_obj(*args, **kwargs)
        return None


class _AssertRaisesContext:
    def __init__(self, expected, test_case, expected_regexp=None):
        self.expected = expected
        self.failureException = test_case.failureException
        self.expected_regexp = expected_regexp

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            try:
                exc_name = self.expected.__name__
            except AttributeError:
                exc_name = str(self.expected)
            msg = f"{exc_name} not raised"
            raise self.failureException(msg)
        if not issubclass(exc_type, self.expected):
            # let unexpected exceptions pass through
            return False
        self.exception = exc_value  # store for later retrieval
        if self.expected_regexp is None:
            return True

        expected_regexp = self.expected_regexp
        if not expected_regexp.search(str(exc_value)):
            msg = f'"{expected_regexp.pattern}" does not match "{exc_value!s}"'
            raise self.failureException(
                msg
            )
        return True
