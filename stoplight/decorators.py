
import inspect
from functools import wraps
import stoplight
from stoplight.exceptions import *
from stoplight.rule import *


def _apply_rule(func, rule, param, getter=None, dispatch=True):
    """Helper function that takes a given rule and value
    and attempts to perform validation on this rule

    :param func: The decorated function for which we are validating input
    :param rule: The rule to validate
    :param param: The parameter that we're validating, if applicable.
       Otherwise, None
    :param getter: A function for retrieving the value to validate
    :param outerrule: If specified, this is an outerrule

    Returns True if the rule was successfully applied and the
    validate succeeded. Returns False if the validation was
    performed and failed. Raises a ValidationProgrammingException
    otherwise
    """
    def _create_failure_info():
        val_failure = stoplight.ValidationFailureInfo()
        val_failure.function = func
        val_failure.parameter = param
        val_failure.parameter_value = value
        val_failure.rule = rule

        return val_failure

    # Are we using a getter other than the one specified in the rule?
    g = getter or rule.getter

    value = g(param)

    try:
        resp = rule.vfunc(value)

        # Ensure that the validation function did not return
        # anything. This is to ensure that it is not a function
        if resp is not None and inspect.isfunction(resp):
            msg = 'Val func returned a function. Rule={0}'
            msg = msg.format(rule.__class__.__name__)

            raise ValidationProgrammingError(msg)

    except ValidationFailed as ex:
        val_failure = _create_failure_info()
        val_failure.ex = ex

        # We always call the error handler at the point point of
        # failure (even if it's a nested rule), then dispatch at
        # the outer-most level
        rule.call_error(val_failure)

        if dispatch is True:
            stoplight.failure_dispatch(val_failure)

        return val_failure

    # Validation on the outer rule was successful,
    for nested_rule in rule.nested_rules:

        # We step through each nested rule, performing the same type of
        out = _apply_rule(func, nested_rule, value,
            nested_rule.getter, dispatch=False)

        if out is not None:
            val_failure = _create_failure_info()
            val_failure.nested_failure = out
            val_failure.ex = out.ex

            stoplight.failure_dispatch(val_failure)

            return val_failure

    # NOTE: If we reach this point, validation was successful


def validate(*freerules, **paramrules):
    """Validates a function's input using the specified set of paramrules."""
    def _validate(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Validate the free rules
            for rule in freerules:
                # Free rules *must* have a getter function to return
                # a value that can be passed into the validation
                # function
                if rule.getter is None:
                    msg = "Free rules must specify a getter. Rule={0}"
                    msg = msg.format(rule.__class__.__name__)
                    raise ValidationProgrammingError(msg)

                if _apply_rule(f, rule, None, rule.getter) is not None:
                    return

            funcparams = inspect.getargspec(f)

            # Holds the list of validated values. Only
            # these values are passed to the decorated function
            outargs = dict()

            param_map = list(zip(funcparams.args, args))

            # Create dictionary that maps parameters passed
            # to their values passed
            param_values = dict(param_map)

            # Bring in kwargs so that we can validate those as well.
            param_values.update(kwargs)

            # Now check for rules and parameters. We should have one
            # rule for every parameter.
            param_names = set(param_values.keys())
            rule_names = set(paramrules.keys())

            missing_rules = list(param_names - rule_names)

            # TODO: for optimization, move this out to a
            # variable since it's immutable for our purposes
            if missing_rules not in [[], ['self']]:
                msg = "Parameter(s) not validated {0}"
                msg = msg.format(missing_rules)
                raise ValidationProgrammingError(msg)

            unassigned_rules = list(rule_names - param_names)

            if unassigned_rules != []:
                msg = "No such parameter for rule(s) {0}"
                msg = msg.format(unassigned_rules)
                raise ValidationProgrammingError(msg)

            for param, rule in paramrules.items():

                # Where can we get the value? It's either
                # the getter on the rule or we default
                # to verifying parameters.
                getval = rule.getter or param_values.get

                if _apply_rule(f, rule, param, getval) is not None:
                    # Validation was not successful
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
            if none_ok is True and value is None:
                return

            if none_ok is not True and value is None:
                msg = 'None value not permitted'
                raise ValidationFailed(msg)

            if empty_ok is True and value == '':
                return

            if empty_ok is not True and value == '':
                msg = 'Empty value not permitted'
                raise ValidationFailed(msg)

            func(value)
        return wrapper
    return inner
