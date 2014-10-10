
import inspect
from functools import wraps
import stoplight
from stoplight.exceptions import *
from stoplight.rule import *


def validate(**rules):
    """Validates a function's input using the specified set of rules."""
    def _validate(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            funcparams = inspect.getargspec(f)

            # Holds the list of validated values. Only
            # these values are passed to the endpoint
            outargs = dict()

            # Create dictionary that maps parameters passed
            # to their values passed
            param_values = dict(zip(funcparams.args, args))

            # Bring in kwargs so that we can validate as well
            param_values.update(kwargs)

            for param, rule in rules.items():

                # Where can we get the value? It's either
                # the getter on the rule or we default
                # to verifying parameters.
                getval = rule.getter or param_values.get

                # Call the validation function, passing
                # the value was retrieved from the getter
                try:
                    value = getval(param)

                    # Ensure that this validation function
                    # did not return a funciton. This
                    # checks that the user did not forget to
                    # execute the outer function of a closure
                    # in the rule declaration

                    resp = rule.vfunc(value)

                    if inspect.isfunction(resp):
                        msg = 'Val func returned a function. Rule={0}'
                        msg = msg.format(rule.__class__.__name__)

                        raise ValidationProgrammingError(msg)

                    # Now validate any nested rules that are part of this
                    # request.
                    for nested_rule in rule.nested_rules:
                        # Note: for 'nested' rules, the value
                        # passed into the getter is the value
                        # of the 'super' parameter.
                        nested_getter = nested_rule.getter
                        nested_val = nested_getter(value)

                        try:
                            resp = nested_rule.vfunc(nested_val)  # throws
                        except ValidationFailed as ex:

                            nested_rule.errfunc()

                            val_failure = stoplight.ValidationFailureInfo()
                            val_failure.function = f
                            val_failure.parameter = param
                            val_failure.parameter_value = value
                            val_failure.rule = rule
                            val_failure.nested_rule = nested_rule
                            val_failure.nested_value = nested_val
                            val_failure.ex = ex

                            stoplight.failure_dispatch(val_failure)

                            return

                        if inspect.isfunction(resp):
                            msg = 'Nest rule validation function ' + \
                                'returned a function'
                            raise ValidationProgrammingError(msg)

                    # If this is a param rule, add the
                    # param to the list of out args
                    if rule.getter is None:
                        outargs[param] = value

                except ValidationFailed as ex:
                    rule.errfunc()

                    val_failure = stoplight.ValidationFailureInfo()
                    val_failure.function = f
                    val_failure.parameter = param
                    val_failure.parameter_value = value
                    val_failure.rule = rule
                    val_failure.ex = ex

                    stoplight.failure_dispatch(val_failure)

                    return

            # Validation was successful, call the wrapped function
            return f(*args, **kwargs)
        return wrapper
    return _validate


def validation_function(func):
    """Decorator for creating a validation function"""
    @wraps(func)
    def inner(none_ok=False, empty_ok=False):
        def wrapper(value, **kwargs):
            if none_ok and value is None:
                return

            if not none_ok and value is None:
                msg = 'None value not permitted'
                raise ValidationFailed(msg)

            if empty_ok and value == '':
                return

            if not empty_ok and value == '':
                msg = 'Empty value not permitted'
                raise ValidationFailed(msg)

            func(value)
        return wrapper
    return inner
