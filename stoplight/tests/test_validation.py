from unittest import TestCase

from stoplight import *
from stoplight.exceptions import *

import os

# TODO: We probably want to move this to a
# test helpers library

VALIDATED_STR = 'validated'


@validation_function
def is_upper(z):
    """Simple validation function for testing purposes
    that ensures that input is all caps
    """
    if z.upper() != z:
        raise ValidationFailed('{0} no uppercase'.format(z))

error_count = 0


def abort(code):
    global error_count
    error_count = error_count + 1

other_vals = dict()
get_other_val = other_vals.get


class DummyRequest(object):
    def __init__(self):
        self.headers = dict(header1='headervalue1')


class DummyResponse(object):
    pass


@validation_function
def is_request(candidate):
    return isinstance(candidate, DummyRequest)


@validation_function
def is_response(candidate):
    return isinstance(candidate, DummyResponse)


class DummyEndpoint(object):

    # This should throw a ValidationProgrammingError
    # when called because the user did not actually
    # call validate_upper.

    # Note: the lambda in this function can never actually be
    # called, so we use no cover here
    @validate(value=Rule(is_upper, lambda: abort(404)))  # pragma: no cover
    def get_value_programming_error(self, value):
        # This function body should never be
        # callable since the validation error
        # should not allow it to be called
        assert False  # pragma: no cover

    @validate(
        value1=Rule(is_upper(), lambda: abort(404)),
        value2=Rule(is_upper(), lambda: abort(404)),
        value3=Rule(is_upper(), lambda: abort(404))
    )  # pragma: no cover
    def get_value_happy_path(self, value1, value2, value3):
        return value1 + value2 + value3

    @validate(
        value1=Rule(is_upper(), lambda: abort(404)),
        value2=Rule(is_upper(empty_ok=True), lambda: abort(404),
            get_other_val),
    )  # pragma: no cover
    def get_value_with_getter(self, value1):
        global other_vals
        return value1 + other_vals.get('value2')

    # Falcon-style endpoint
    @validate(
        request=Rule(is_request(), lambda: abort(404)),
        response=Rule(is_response(), lambda: abort(404)),
        value=Rule(is_upper(), lambda: abort(404)),
        header1=Rule(is_upper(), lambda: abort(404))
    )
    def get_falcon_style(self, request, response, value, header1):
        return value


class TestValidationFunction(TestCase):

    def test_empty_ok(self):
        is_upper(empty_ok=True)('')

        with self.assertRaises(ValidationFailed):
            is_upper()('')

        is_upper(none_ok=True)(None)

        with self.assertRaises(ValidationFailed):
            is_upper()(None)


class TestValidationDecorator(TestCase):

    def setUp(self):
        self.ep = DummyEndpoint()

    def test_programming_error(self):
        with self.assertRaises(ValidationProgrammingError):
            self.ep.get_value_programming_error('AT_ME')

    def test_falcon_style(self):
        global error_count

        request = DummyRequest()
        response = DummyResponse()

        oldcount = error_count

        self.ep.get_falcon_style(response, 'HELLO')

        self.assertEqual(oldcount, error_count)

    def test_happy_path_and_validation_failure(self):
        global error_count
        # Should not throw
        res = self.ep.get_value_happy_path('WHATEVER', 'HELLO', 'YES')
        self.assertEqual('WHATEVERHELLOYES', res)

        # Validation should have failed, and
        # we should have seen a tick in the error count
        oldcount = error_count
        res = self.ep.get_value_happy_path('WHAtEVER', 'HELLO', 'YES')
        self.assertEqual(oldcount + 1, error_count)

        # Check passing a None value. This decorator does
        # not permit none values.
        oldcount = error_count
        res = self.ep.get_value_happy_path(None, 'HELLO', 'YES')
        self.assertEqual(oldcount + 1, error_count)

    def test_getter(self):
        global other_vals

        other_vals['value2'] = 'HELLO'

        # Now have our validation actually try to
        # get those values

        # This should succeed
        res = self.ep.get_value_with_getter('TEST')
        self.assertEqual('TESTHELLO', res)

        # check empty_ok
        other_vals['value2'] = ''
        res = self.ep.get_value_with_getter('TEST')
        self.assertEqual('TEST', res)
