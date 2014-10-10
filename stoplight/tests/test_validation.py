from unittest import TestCase

import stoplight
from stoplight import *
from stoplight.exceptions import *

import os

VALIDATED_STR = 'validated'


@validation_function
def is_upper(z):
    """Simple validation function for testing purposes
    that ensures that input is all caps
    """
    if z.upper() != z:
        raise ValidationFailed('{0} is not uppercase'.format(z))


@validation_function
def is_json(candidate):
    import json
    try:
        # Note: this is an example only and probably not
        # a good idea to use this in production. Use
        # a real json validation framework
        json.loads(candidate)
    except ValueError:
        raise ValidationFailed('Input must be valid json')


def is_type(t):
    @validation_function
    def func(value):
        # Make sure the user actually passed us a type
        if not isinstance(t, type):
            raise TypeError('Type of "type" is required')

        if not isinstance(value, t):
            raise ValidationFailed('Input is incorrect type')
    return func

error_count = 0


def abort(code):
    global error_count
    error_count = error_count + 1

other_vals = dict()
get_other_val = other_vals.get


class DummyRequest(object):

    def __init__(self):
        self.headers = {
            'header1': 'headervalue1',
            'X-Position': '32'
        }

        self.body = ""


class DummyResponse(object):
    pass


@validation_function
def is_request(candidate):
    if not isinstance(candidate, DummyRequest):
        raise ValidationFailed('Input must be a request')


@validation_function
def is_response(candidate):
    if not isinstance(candidate, DummyResponse):
        raise ValidationFailed('Input must be a response')


ResponseRule = Rule(is_response(), lambda: abort(404))
UppercaseRule = Rule(is_upper(), lambda: abort(404))


class RequestRule(Rule):

    def __init__(self, *nested_rules):
        """Constructs a new Rule for validating requests. Any
        nested rules needed for validating parts of the request
        (such as headers, query string params, etc) should
        also be passed in.

        :param nested_rules: Any sub rules that also should be
          used for validation
        """
        # If we get something that's not a request here,
        # something bad happened in the server (i.e.
        # maybe a programming error), so return a 500
        Rule.__init__(self, vfunc=is_request(),
                      errfunc=lambda: abort(500),
                      nested_rules=list(nested_rules))


class HeaderRule(Rule):

    def __init__(self, headername, vfunc, errfunc):
        getter = lambda r: r.headers.get(headername)
        Rule.__init__(self, vfunc=vfunc, getter=getter, errfunc=errfunc)


class BodyRule(Rule):

    def __init__(self, vfunc, errfunc):
        getter = lambda req: req.body
        Rule.__init__(self, vfunc=vfunc, getter=getter, errfunc=errfunc)


PositionRule = HeaderRule("X-Position", is_type(str)(), lambda: abort(404))
JsonBodyRule = BodyRule(is_json(empty_ok=True), lambda: abort(404))
PositionRuleProgError = HeaderRule(
    "X-Position", is_type(str), lambda: abort(404))


def abort_and_raise(msg):
    raise RuntimeError(msg)


FunctionalUppercaseRule = Rule(is_upper(),
                               lambda: abort_and_raise('not uppercase'))


@validate(value=FunctionalUppercaseRule)
def FunctionValidation(value):
    return value


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
        value=Rule(is_upper(), lambda: abort(404))
    )
    def get_falcon_style(self, request, response, value):
        return value

    # Falcon-style w/ delcared rules
    @validate(request=RequestRule(), response=ResponseRule,
              value=UppercaseRule)
    def get_falcon_style2(self, request, response, value):
        return value

    # Stoplight allows the user to express rules, alias them,
    # then clearly know what is being validated.
    @validate(
        request=RequestRule(PositionRule, JsonBodyRule),
        response=ResponseRule,
        value=Rule(is_type(int)(), lambda: abort(400))
    )
    def do_something(self, request, response, value):
        return value

    # Use a position rule that has a programming error.
    # This should throw
    @validate(
        request=RequestRule(PositionRuleProgError, JsonBodyRule),
        response=ResponseRule,
        value=Rule(is_type(int)(), lambda: abort(400))
    )
    def do_something_programming_error(self, request, response, value):
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

    def test_function_style_validation(self):

        positive_cases = [
            'A', 'B', 'C',
            'AA', 'AB', 'CZ',
            'RED', 'GREEN', 'BLUE',
        ]
        negative_cases = [
            'z', 'y', 'z',
            'ww', 'vv', 'uu',
            'serial', 'cereal', 'surreal'
        ]

        for case in positive_cases:
            self.assertEqual(case, FunctionValidation(case))

        for case in negative_cases:
            with self.assertRaises(RuntimeError):
                FunctionValidation(case)

    def test_programming_error(self):
        with self.assertRaises(ValidationProgrammingError):
            self.ep.get_value_programming_error('AT_ME')

    def test_callbacks(self):

        global error_count

        request = DummyRequest()
        response = DummyResponse()

        # Let's register a bad callback that throws. This is to ensure
        # that doing so would not prevent other callbacks from
        # happening

        def bad_cb(x):
            raise Exception("Bad callback")

        stoplight.register_callback(bad_cb)

        valfailures = []

        # Force an error. X-Position is required
        # to be a string type, so passing an int
        # should force a validation error
        request.headers = {'X-Position': 9876}

        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount + 1, error_count)

        # Our callback wasn't registered, so this should
        # have resulted no change to response_obj
        self.assertEqual(len(valfailures), 0)

        cb = lambda x: valfailures.append(x)

        # Now register a callback and try again
        stoplight.register_callback(cb)

        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount + 1, error_count)

        self.assertEqual(len(valfailures), 1)

        # Try again, should increment the count again
        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount + 1, error_count)

        self.assertEqual(len(valfailures), 2)
        stoplight.unregister_callback(cb)
        stoplight.unregister_callback(bad_cb)

        # removing a bogus callback should fail silently
        stoplight.unregister_callback(lambda x: None)

        # Now, let's get the second item and do some
        # validations on it
        obj = valfailures[1]

        # Parameter-level stuff
        self.assertIsInstance(obj.rule, RequestRule)
        self.assertEqual(obj.function.__name__, 'do_something')
        self.assertEqual(obj.parameter, 'request')
        self.assertIsInstance(obj.parameter_value, DummyRequest)

        # nested level stuff
        self.assertIsInstance(obj.nested_rule, HeaderRule)
        self.assertEqual(obj.nested_value, 9876)

        # This is the exception that should have been thrown
        self.assertIsInstance(obj.ex, ValidationFailed)

        pretty = str(obj)

        # Let's ensure that some basic information is in there
        self.assertIn('RequestRule', pretty)
        self.assertIn(obj.function.__name__, pretty)
        self.assertIn(obj.parameter, pretty)
        self.assertIn(str(obj.nested_value), pretty)
        self.assertIn(str(obj.ex), pretty)

    def test_falcon_style(self):

        global error_count

        request = DummyRequest()
        response = DummyResponse()

        # Try to call with missing params. The validation
        # function should never get called
        oldcount = error_count
        self.ep.get_falcon_style(response, 'HELLO')
        self.assertEqual(oldcount + 1, error_count)

        # Try to pass a string to a positional argument
        # where a response is expected
        oldcount = error_count
        self.ep.get_falcon_style(request, "bogusinput", 'HELLO')
        self.assertEqual(oldcount + 1, error_count)

        # Pass in as kwvalues with good input but out of
        # typical order (should succeed)
        oldcount = error_count
        self.ep.get_falcon_style(response=response, value='HELLO',
                                 request=request)
        self.assertEqual(oldcount, error_count)

        # Pass in as kwvalues with good input but out of
        # typical order with an invalid value (lower-case 'h')
        oldcount = error_count
        self.ep.get_falcon_style(response=response, value='hELLO',
                                 request=request)
        self.assertEqual(oldcount + 1, error_count)

        # Pass in as kwvalues with good input but out of typical order
        # and pass an invalid value. Note that here the response is
        # assigned to request, etc.
        oldcount = error_count
        self.ep.get_falcon_style(response=request, value='HELLO',
                                 request=response)
        self.assertEqual(oldcount + 1, error_count)

        # Happy path
        oldcount = error_count
        self.ep.get_falcon_style(request, response, 'HELLO')
        self.assertEqual(oldcount, error_count)

        # This should fail because 3 should be a str, not
        # an int
        oldcount = error_count
        self.ep.do_something(request, response, '3')
        self.assertEqual(oldcount + 1, error_count)

        # This should now be successful
        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount, error_count)

        # Now change the request so that the body is
        # something not considered valid json. This should
        # cause a failure of the nested error
        request.body = "{"
        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount + 1, error_count)

        # Switch request back to normal. Should succeed
        request.body = ""
        oldcount = error_count
        self.ep.do_something(request, response, 3)
        self.assertEqual(oldcount, error_count)

        # Now try one with a programming erro
        oldcount = error_count

        with self.assertRaises(ValidationProgrammingError) as ctx:
            self.ep.do_something_programming_error(request, response, 3)

        self.assertEqual(oldcount, error_count)

    def test_falcon_style_decld_rules(self):
        # The following tests repeat the above
        # tests, but this time they test using the
        # endpoint with the rules being declared
        # separately. See get_falcon_style2 above

        global error_count

        request = DummyRequest()
        response = DummyResponse()

        # Try to call with missing params. The validation
        # function should never get called
        oldcount = error_count
        self.ep.get_falcon_style2(response, 'HELLO')
        self.assertEqual(oldcount + 1, error_count)

        # Try to pass a string to a positional argument
        # where a response is expected
        oldcount = error_count
        self.ep.get_falcon_style2(request, "bogusinput", 'HELLO')
        self.assertEqual(oldcount + 1, error_count)

        # Pass in as kwvalues with good input but out of
        # typical order (should succeed)
        oldcount = error_count
        self.ep.get_falcon_style2(response=response, value='HELLO',
                                  request=request)
        self.assertEqual(oldcount, error_count)

        # Pass in as kwvalues with good input but out of
        # typical order with an invalid value (lower-case 'h')
        oldcount = error_count
        self.ep.get_falcon_style2(response=response, value='hELLO',
                                  request=request)
        self.assertEqual(oldcount + 1, error_count)

        # Pass in as kwvalues with good input but out of typical order
        # and pass an invalid value. Note that here the response is
        # assigned to request, etc.
        oldcount = error_count
        self.ep.get_falcon_style2(response=request, value='HELLO',
                                  request=response)
        self.assertEqual(oldcount + 1, error_count)

        # Happy path
        oldcount = error_count
        self.ep.get_falcon_style2(request, response, 'HELLO')
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
