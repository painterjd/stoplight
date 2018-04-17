import os
import re
import threading
from unittest import TestCase

import mock

import stoplight
from stoplight import *
from stoplight.exceptions import *

VALIDATED_STR = 'validated'
globalctx = threading.local()

IS_UPPER_REGEX = re.compile('^[A-Z]*$')


@validation_function
def is_upper(z):
    """Simple validation function for testing purposes
    that ensures that input is all caps
    """
    if not IS_UPPER_REGEX.match(z):
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


detailed_errors = list()


def abort_with_details(code, details):
    global error_count, detailed_errors
    error_count = error_count + 1

    detailed_errors.append(detailed_errors)


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
        def _onerror():
            return abort(500)

        # If we get something that's not a request here,
        # something bad happened in the server (i.e.
        # maybe a programming error), so return a 500
        Rule.__init__(self, vfunc=is_request(),
                      errfunc=_onerror,
                      nested_rules=list(nested_rules))


class Matryoshka(object):

    def __init__(self, name, inner=None):

        """Constructs a new Matryoshka

        :param name: The name of this Matryoshka
        :param inner: The Matryoshka contained therein
        """
        self._name = name
        self._inner = inner

    @property
    def inner(self):
        return self._inner

    @property
    def name(self):
        return self._name


# Example showing how to use a closure and a validation
# function simultaneously.
def has_name(name):
    @validation_function
    def _inner(obj):
        if name != obj.name:
            msg = "Name '{0}' does not match '{1}"
            msg = msg.format(obj.name, name)
            raise ValidationFailed(msg)

    return _inner


class MatryoshkaRule(Rule):
    def __init__(self, name, *nested_rules, **kwargs):
        """Constructs a new Matryoshka rule"""
        self.matryoshka_name = name

        outer = kwargs.get("outer")
        getter = kwargs.get("getter")

        def _onerror():
            return abort(500)

        def _getter(matryoshka):
            return matryoshka.inner

        Rule.__init__(self, vfunc=has_name(name)(),
            getter=getter if outer else _getter,
            errfunc=_onerror, nested_rules=list(nested_rules))


class HeaderRule(Rule):

    def __init__(self, headername, vfunc, errfunc):
        def getter(req):
            return req.headers.get(headername)

        Rule.__init__(self, vfunc=vfunc, getter=getter, errfunc=errfunc)


class BodyRule(Rule):

    def __init__(self, vfunc, errfunc):
        def _getter(req):
            return req.body

        Rule.__init__(self, vfunc=vfunc, getter=_getter, errfunc=errfunc)


PositionRule = HeaderRule("X-Position", is_type(str)(), lambda: abort(404))

PositionRuleDetailed = HeaderRule("X-Position", is_type(str)(),
    lambda err: abort_with_details(404, err))

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

    # Stoplight allows the user to express rules, alias them,
    # then clearly know what is being validated.
    @validate(
        request=RequestRule(PositionRuleDetailed),
        response=ResponseRule,
        value=Rule(is_type(int)(), lambda err: abort_with_details(400, err))
    )
    def detailed_error_ep(self, request, response, value):
        return value

    # Validation function with only global-scopped validations
    @validate(Rule(is_upper(), lambda err: abort_with_details(400, err),
        lambda z: globalctx.testvalue))
    def do_something_global(self):
        return globalctx.testvalue

    @validate(Rule(is_upper(), lambda err: abort_with_details(400, err)))
    def free_rule_no_getter(self):
        return

    # Test nested rules
    @validate(param=MatryoshkaRule("large",
        MatryoshkaRule("med", MatryoshkaRule("small")),
        outer=True)
    )
    def nested_rules(self, param):
        return param.name

    # Demonstrates a programming error. Every parameter but 'self' must
    # be validated.
    @validate(param1=UppercaseRule)
    def missing_parameters(self, param1, param2):
        return param1 + param2

    # Demonstrates passing a rule for a parameter that doesn't actually
    # exist
    @validate(param1=UppercaseRule, param2=UppercaseRule, param3=UppercaseRule)
    def superfluous_parameter(self, param1, param2):
        return param1 + param2


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

    def test_missing_parameters(self):
        with self.assertRaises(ValidationProgrammingError):
            self.ep.missing_parameters('value1', 'value2')

    def test_superfluous_parameter(self):
        with self.assertRaises(ValidationProgrammingError):
            self.ep.superfluous_parameter('value1', 'value2')

    def test_function_style_validation(self):

        positive_cases = [
            'A', 'B', 'C',
            'AA', 'AB', 'CZ',
            'RED', 'GREEN', 'BLUE',
        ]
        negative_cases = [
            'z', 'y', 'z',
            'ww', 'vv', 'uu',
            'serial', 'cereal', 'surreal',
            '}', '{', '\\}', '\\{', r'\{', r'\}'
        ]

        for case in positive_cases:
            self.assertEqual(case, FunctionValidation(case))

        for case in negative_cases:
            with self.assertRaises(RuntimeError):
                FunctionValidation(case)

    def test_nested_rules(self):
        global error_count

        matryoshka_small = Matryoshka("small")
        matryoshka_med = Matryoshka("med", matryoshka_small)
        matryoshka_large = Matryoshka("large", matryoshka_med)

        # This should succeed!
        oldcount = error_count
        out = self.ep.nested_rules(matryoshka_large)
        self.assertEqual(oldcount, error_count)
        self.assertEqual(matryoshka_large.name, out)

        # This should fail
        oldcount = error_count
        self.ep.nested_rules(matryoshka_small)
        self.assertEqual(oldcount + 1, error_count)

    def test_programming_error(self):
        with self.assertRaises(ValidationProgrammingError):
            self.ep.get_value_programming_error('AT_ME')

    def test_detailed_errfuncs(self):
        global error_count, detailed_errors

        request = DummyRequest()
        response = DummyResponse()

        """
        # Should succeed
        oldcount = error_count
        self.ep.detailed_error_ep(request, response, 1)
        self.assertEqual(oldcount, error_count)

        # Should Fail Validation
        detailed_errors = []
        oldcount = error_count
        self.ep.detailed_error_ep(request, response, 'blah')
        self.assertEqual(oldcount + 1, error_count)
        self.assertEqual(len(detailed_errors), 1)
        """

        # Should Fail Validation
        detailed_errors = []
        oldcount = error_count
        request.headers = {'X-Position': 1}
        self.ep.detailed_error_ep(request, response, 1)
        self.assertEqual(oldcount + 1, error_count)
        self.assertEqual(len(detailed_errors), 1)

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

        def cb(x):
            valfailures.append(x)

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
        self.assertIsInstance(obj.nested_failure.rule, HeaderRule)
        self.assertEqual(obj.nested_failure.parameter_value, 9876)

        # This is the exception that should have been thrown
        self.assertIsInstance(obj.ex, ValidationFailed)

        pretty = str(obj)

        # Let's ensure that some basic information is in there
        self.assertIn('RequestRule', pretty)
        self.assertIn(obj.function.__name__, pretty)
        self.assertIn(obj.parameter, pretty)
        self.assertIn(str(obj.nested_failure), pretty)
        self.assertIn(str(obj.ex), pretty)

    def test_falcon_style(self):

        global error_count

        request = DummyRequest()
        response = DummyResponse()

        # Try to call with missing params. The validation
        # function should never get called
        with self.assertRaises(ValidationProgrammingError) as ctx:
            self.ep.get_falcon_style(response, 'HELLO')

        # Try to pass a string to a positional argument
        # where a response is expected
        oldcount = error_count
        self.ep.get_falcon_style(request, "bogusinput", 'HELLO')
        self.assertEqual(oldcount + 1, error_count)

        # Pass in as kwargs with good input but out of
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
        with self.assertRaises(ValidationProgrammingError) as ctx:
            self.ep.get_falcon_style2(response, 'HELLO')

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

    def test_global_ctx(self):
        global globalctx
        global error_count

        globalctx.testvalue = "SOMETHING"  # Should succeed
        res = self.ep.do_something_global()
        self.assertEqual(globalctx.testvalue, "SOMETHING")

        oldcount = error_count
        globalctx.testvalue = "Something"  # Should succeed
        res = self.ep.do_something_global()
        self.assertEqual(oldcount + 1, error_count)

    def test_free_rule_no_getter(self):
        with self.assertRaises(ValidationProgrammingError):
            res = self.ep.free_rule_no_getter()

    def test_validation_failure_deprecation_warning(self):
        with mock.patch('warnings.warn') as mock_warning:
            ValidationFailed('hello {0}', 'world')
            self.assertEqual(mock_warning.call_count, 1)

    def test_validation_programmering_error_deprecation_warning(self):
        with mock.patch('warnings.warn') as mock_warning:
            ValidationProgrammingError('hello {0}', 'world')
            self.assertEqual(mock_warning.call_count, 1)
