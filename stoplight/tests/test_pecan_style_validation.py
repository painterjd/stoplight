import os
import sys
import json

import pecan
from pecan.testing import load_test_app
import testtools
from webtest import app

from stoplight import rule
from stoplight import decorators
from stoplight import exceptions
from stoplight import helpers

os.environ['PECAN_CONFIG'] = os.path.join(os.path.dirname(__file__),
                                          'config.py')
# For noese fix
sys.path = [os.path.abspath(os.path.dirname(__file__))] + sys.path


@decorators.validation_function
def is_valid_json(r):
    """Simple validation function for testing purposes
    that ensures that input is all caps
    """
    if len(r.body) == 0:
        return
    else:
        try:
            json.loads(r.body.decode('utf-8'))
        except Exception as e:
            e
            raise exceptions.ValidationFailed('Invalid JSON string')
        else:
            return

error_count = 0


class DummyPecanEndpoint(object):

    @pecan.expose()
    @decorators.validate(
        request=rule.Rule(is_valid_json(),
                          lambda: pecan.abort(400),
                          helpers.pecan_getter)
    )
    def index(self):
        return "Hello, World!"


class PecanEndPointFunctionalTest(testtools.TestCase):

    """A Simple PecanFunctionalTest base class that sets up a
    Pecan endpoint (endpoint class: DummyPecanEndpoint)
    """

    def setUp(self):
        self.app = load_test_app(os.path.join(os.path.dirname(__file__),
                                              'config.py'
                                              ))
        super(PecanEndPointFunctionalTest, self).setUp()

    def tearDown(self):
        pecan.set_config({}, overwrite=True)
        super(PecanEndPointFunctionalTest, self).tearDown()


class TestValidationDecoratorsPecan(PecanEndPointFunctionalTest):

    def test_pecan_endpoint_put(self):
        resp = self.app.post(
            '/',
            headers={
                "Content-Type": "application/json;charset=utf-8"})
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body.decode('utf-8'), "Hello, World!")
        with self.assertRaisesRegexp(app.AppError, "400 Bad Request"):
            self.app.post('/', params='{',
                          headers={"Content-Type":
                                   "application/json;charset=utf-8"})
