#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import OrderedDict
import re
from datetime import datetime
from collections import defaultdict
from itertools import chain

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ValidationError(Exception):
    pass


class Field:
    def __init__(self, null_values=[''], required=True, nullable=False):
        self.required = required
        self.nullable = nullable
        self.null_values = null_values

    def valid(self, value):
        if value is None:
            return not self.required
        elif value in self.null_values:
            return self.nullable
        try:
            self.validate(value)
        except ValidationError:
            return False
        return True

    def validate(self, value):
        pass


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, str):
            raise ValidationError


class ArgumentsField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[{}], **kwargs)

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValidationError


class EmailField(CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        super().validate(value)
        if '@' not in value:
            raise ValidationError


class PhoneField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=["", 0], **kwargs)

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, (str, int)):
            raise ValidationError
        value = str(value)
        if re.match(r'7\d{10}$', value) is None:
            raise ValidationError


class DateField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        super().validate(value)
        try:
            date = datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            raise ValidationError


class BirthDayField(DateField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        super().validate(value)
        delta = datetime.now() - datetime.strptime(value, "%d.%m.%Y")
        if delta.days < 0 or delta.days > 70*365:
            raise ValidationError


class GenderField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[None], **kwargs)

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, int):
            raise ValidationError
        if value not in GENDERS:
            raise ValidationError


class ClientIDsField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[[]], **kwargs)

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, list):
            raise ValidationError
        if not all(isinstance(v, int) for v in value):
            raise ValidationError


class DeclarativeFields(type):
    """Collect Fields declared on the base classes."""
    def __new__(mcs, name, bases, attrs):
        fields = []
        for key, value in list(attrs.items()):
            if isinstance(value, Field):
                fields.append((key, value))
                attrs.pop(key)
        attrs['fields'] = OrderedDict(fields)

        return super(DeclarativeFields, mcs).__new__(mcs, name, bases, attrs)


class BaseRequest(metaclass=DeclarativeFields):
    def __init__(self, req_args=None):
        self.req_args = req_args
        self.errors = []

    def __getattr__(self, attr):
        return self.req_args.get(attr)

    def is_valid(self):
        self.errors = []
        for field_name, field in self.fields.items():
            field_data = self.req_args.get(field_name)
            if not field.valid(field_data):
                self.errors.append("{}:{} invalid".format(field_name,
                                                          field_data))
                logging.error("{}:{} invalid".format(field_name, field_data))
        return not self.errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def get_response(self, ctx, store, is_admin=False):
        ctx["nclients"] = len(self.client_ids)
        ids = self.client_ids
        r = {i: scoring.get_interests(store, i) for i in ids}
        return r, OK


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    pair_fields = [("phone", "email"),
                   ("first_name", "last_name"),
                   ("gender", "birthday")]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_valid(self):
        if not super().is_valid():
            return False
        return self.check_pair()

    def check_pair(self):
        for f1, f2 in type(self).pair_fields:
            d1 = self.req_args.get(f1)
            d2 = self.req_args.get(f2)

            if (d1 is not None and d2 is not None and
                    d1 not in self.fields[f1].null_values and
                    d2 not in self.fields[f2].null_values):
                return True

        self.errors.append("The are no invalid pair fields")
        return False

    def get_response(self, ctx, store, is_admin=False):
        ctx["has"] = [f for f in self.req_args if f not in self.fields[f].null_values]
        score = 42
        if not is_admin:
            score = scoring.get_score(store, self.phone, self.email,
                                      self.birthday, self.gender,
                                      self.first_name, self.last_name)
        return {"score": score}, OK


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        date = datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
        digest = hashlib.sha512(date.encode('utf-8')).hexdigest()
    else:
        date = request.account + request.login + SALT
        digest = hashlib.sha512(date.encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    router = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest
    }
    logging.info("request: {}".format(request))

    req_base = MethodRequest(request.get('body'))
    if not req_base.is_valid():
        return ",".join(req_base.errors), INVALID_REQUEST
    if not check_auth(req_base):
        return "", FORBIDDEN

    try:
        req = router[req_base.method](req_base.arguments)
        if not req.is_valid():
            return ",".join(req.errors), INVALID_REQUEST
    except KeyError:
        return "", NOT_FOUND

    return req.get_response(ctx, store, req_base.is_admin)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string.decode("utf-8"))
        except Exception as e:
            logging.exception("Unexpected error: %s" % e)
            code = BAD_REQUEST
        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
