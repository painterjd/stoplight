"""Stoplight -- an input validation framework for Python

Every good programmer should know that input validation is the first and
best step at implementing application-level security for your product.
Unvalidated user input leads to issues such as SQL injection, javascript
injection and cross-site scripting attacks, etc.

More and more applications are being written for python. Unfortunately,
not many frameworks provide for reasonable input validation techniques
and when the do, the frameworks tend further tie your application
into that framework.

For more complex projects that must supply more input validations, a
frame-work based validation framework becomes even more useless because
the validations must be done in different ways for each transport,
meaning that the chance of a programmer missing a crucial validation
is greatly increased.

A very common programming paradigm for wsgi-based applications is for
applications to expose RESTful endpoints as method members of a
controller class. Typical input validation results in logic built-in
to each function. This makes validating the input very tedious.

Stoplight aims to provide a nice, convenient and flexible way to
validate user input using a simple decorator.
"""

import inspect

from stoplight.rule import *
from stoplight.exceptions import *
from stoplight.decorators import *

_callbacks = set()


class ValidationFailureInfo(object):
    """Describes information related to a particular validation
    failure."""

    def __init__(self, **kwargs):
        self._function = kwargs.get("function")
        self._rule = kwargs.get("rule")
        self._nested_failure = kwargs.get("nested_failure")
        self._param = kwargs.get("parameter")
        self._param_value = kwargs.get("parameter_value")
        self._param_value = kwargs.get("ex")

    @property
    def function(self):
        """The function whose input was being validated."""
        return self._function

    @function.setter
    def function(self, value):
        self._function = value

    @property
    def rule(self):
        """The rule that generated the error."""
        return self._rule

    @rule.setter
    def rule(self, value):
        self._rule = value

    @property
    def nested_failure(self):
        return self._nested_failure

    @nested_failure.setter
    def nested_failure(self, value):
        self._nested_failure = value

    @property
    def parameter(self):
        """The name of the parameter that failed validation."""
        return self._param

    @parameter.setter
    def parameter(self, value):
        self._param = value

    @property
    def parameter_value(self):
        """The value that was passed to the parameter"""
        return self._param_value

    @parameter_value.setter
    def parameter_value(self, value):
        self._param_value = value

    @property
    def ex(self):
        """The exception that was thrown by the validation function"""
        return self._ex

    @ex.setter
    def ex(self, value):
        self._ex = value

    def __str__(self):
        msg = "Validation Failed ["
        msg += "filename={0}, ".format(
            inspect.getsourcefile(self.function))
        msg += "function={0}, ".format(
            self.function.__name__)
        msg += "rule={0}, ".format(self.rule.__class__.__name__)
        msg += "param={0}, ".format(self.parameter)
        msg += "param_value={0}, ".format(self.parameter_value)

        if self.nested_failure is not None:  # pragma: no cover
            msg += "nested_failure={0}".format(self.nested_failure)

        msg += "ex={0}".format(self.ex)
        msg += "]"

        return msg


def register_callback(callback_func):
    """This function will register a callback to be called in case
    a rule fails to validate input.

    This function will be called with information about each failure. The
    validation callback function should expect a single variable which
    will be a ValidationFailureInformation object.

    This functionality is intended for and probably most useful for logging.
    """
    global _callbacks
    _callbacks.add(callback_func)


def unregister_callback(callback_func):
    """Unregisters the specified callback function"""
    if callback_func in _callbacks:
        _callbacks.remove(callback_func)


def failure_dispatch(failureinfo):
    """Sends the specified failure information to all registered callback
    handlers.

    :param failureinfo: An instance of ValidationFailureInfo describing the
                        failure
    """
    global _callbacks

    for cb in _callbacks:
        assert isinstance(failureinfo, ValidationFailureInfo)

        try:
            cb(failureinfo)
        except Exception as ex:
            # If a particular callback throws an exception, we do not want
            # that to prevent subsequent callbacks from happening, so we
            # catch and squash this error and write it to stderr
            import sys
            sys.stderr.write("ERROR: Dispatch function threw an exception.")
            sys.stderr.write(str(ex))
            sys.stderr.flush()
