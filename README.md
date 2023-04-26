Stoplight [![Build](https://github.com/painterjd/stoplight/actions/workflows/python-package.yml/badge.svg)](https://github.com/painterjd/stoplight/actions/workflows/python-package.yml)
=========  

test pr 

Stoplight -- An Input Validation Framework for Python

Why Validate User Input?
------------------------
Input validation is the most basic, first step to adding security to any application that accepts untrusted user input. Volumes have been written on the subject, but the gist is to reduce the attack surface of your application by sanitizing all user input so that it meets a very tight set of criteria needed just for the application, and nothing more. The most common type of attack prevented by input validation is [Code Injection](http://en.wikipedia.org/wiki/Code_injection). 

A great number of user input vulnerabilities (i.e. [Shellshock](http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29)) could be avoided almost entirely if user input were sanitized. 

Example
-------
Let's say that our application is accepting a US Phone Number only. In that case, our application should only need to accept NNN-NNN-NNNN where N is a digit from 0-9. If the user passes anything else, we can throw it away. 

The problem that stoplight aims to address is the intermixing of input validation logic with application logic (in particular with RESTful/REST-like API frameworks). Sometimes they are inseparable, but in almost all cases, they are not. So let's look at the above-mentioned phone number example.

Almost all of today's API frameworks work in a similar manner -- you declare a function that defines an endpoint and the framework calls the function when an HTTP request comes in from a client.

```python
def post(self, account_id, phone_number):
    if not is_valid_account_id(account_id):
        handle_bad_account_id() 
        
    if not is_valid_phone_number(phone_number):
        handle_bad_phone_number() 
    
    model.set_phone_number(account_id, phone_number)
```

This is a simple, contrived example. Typically things start getting much more complex. For certain HTTP verbs, a user will want different responses returned. There may be other things to accomplish as well.

In Stoplight, we would validate the input like so:

```python
@validate(account_id=AccountIdRule, phone_number=PhoneNumberRule)
def post(self, account_id, phone_number):
    model.set_phone_number(account_id, phone_number)
```

This allows us to effectively separate our "input validation" logic from "business logic". 

Rules are fairly simple to create. For example, here is how one might declare the PhoneNumberRule

```python
PhoneNumberRule = Rule(is_validate_phone_number(), lambda: abort(404))
```

And of course, that leads us to is_valid_phone_number() declaration.

```python
@validation_function
def is_valid_phone_number(candidate):
    if (phone_regex.match(candidate) is None):
        msg = 'Not a valid phone number: {0}'
        msg = msg.format(candidate)
        raise ValidationFailed(msg)
```

This allows us to separate validation from transports (imagine an API where you must support HTTP and ZMQ, for example). It also allows us to centralize validation logic and write separate tests for the validation rules.

Other Features:
---------------
 * Ensures that all parameters (positional and keyword) are all validated. If they are not validated, a ValidationProgrammingError is raised.
 * Allows validation of globally-scoped values (think items in thread local storage, as is done in the Pecan framework)
 
Caveats (TODO):
---------------
 * Overhead. Such is the nature of Python with decorators. 

Documentation:
--------------
The project is being documented at readthedocs [here](http://stoplight.readthedocs.org/en/latest/). For other examples, please see the unit tests. 
