"""
Some useful getters for thread local request style validation
"""


def pecan_getter(parm):
    """pecan getter"""
    pecan_module = __import__('pecan', globals(), locals(), ['request'])
    return getattr(pecan_module, 'request')


# def flask_getter(parm):
#     pecan_module = __import__('flask', globals(), locals(), ['request'])
#     return getattr(pecan_module, 'request')
