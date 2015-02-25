stoplight [![Build Status](https://api.travis-ci.org/painterjd/stoplight.png)](https://travis-ci.org/painterjd/stoplight)
=========

Stoplight -- An Input Validation Framework for Python

Why validate your input? Validating untrusted user input is the best first step any programmer to take to develop secure application code. Programmers often validate their input, but the validation ends up being wrapped up into application code which invariably results in validations being missed.

Stoplight aims to make input validation much more explicit in code, making it easier for porgrammers to catch any missed inputs.

A simple example: 

We start by creating a validation function:

    @validation_function
    def is_upper(z):
        """Simple validation function for testing purposes
        that ensures that input is all caps
        """
        if z.upper() != z:
            raise ValidationFailed('{0} is not uppercase'.format(z))
            
The function is fairly  self-explanatory -- if the validation fails, we raise a VaildationFailed exception. Otherwise, the function just does nothing.

