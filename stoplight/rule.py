
from collections import namedtuple

# ValidationRule = namedtuple('ValidationRule', 'vfunc errfunc getter,
# subrules')

# def Rule(vfunc, on_error, getter=None, subrules=[]):
#    """Constructs a single validation rule. A rule effectively
#    is saying "I want to validation this input using
#    this function and if validation fails I want this (on_error)
#    to happen.
#
#    :param vfunc: The function used to validate this param
#    :param on_error: The function to call when an error is detected
#    :param value_src: The source from which the value can be
#        This function should take a value as a field name
#        as a single param.
#    :param src: Th
#    """
#    return ValidationRule(vfunc=vfunc, errfunc=on_error, getter=getter,
#        subrules=subrules)


class Rule(object):

    def __init__(self, vfunc, errfunc, getter=None, nested_rules=None):
        """Constructs a single validation rule. A rule effectively
        is saying "I want to validation this input using
        this function and if validation fails I want this (on_error)
        to happen.

        :param vfunc: The function used to validate this param
        :param on_error: The function to call when an error is detected
        :param value_src: The source from which the value can be
            This function should take a value as a field name
            as a single param.
        """
        self._vfunc = vfunc
        self._errfunc = errfunc
        self._getter = getter
        self._nested = nested_rules or []

    @property
    def vfunc(self):
        return self._vfunc

    @property
    def errfunc(self):
        return self._errfunc

    @property
    def getter(self):
        return self._getter

    @property
    def nested_rules(self):
        return self._nested
