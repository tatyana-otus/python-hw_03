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


class Field:
    def __init__(self, null_values=[''], required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.null_values = null_values
        self.validators = []

    def valid(self, value):
        if value is None:
            return not self.required
        elif value in self.null_values:
            return self.nullable
        else:
            for v in self.validators:
                if not v(value):
                    return False
        return True


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(CharField.is_string)

    @staticmethod
    def is_string(value):
        return isinstance(value, str)


class ArgumentsField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[{}], **kwargs)
        self.validators.append(ArgumentsField.is_dict)

    @staticmethod
    def is_dict(value):
        return isinstance(value, dict)


class EmailField(CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(EmailField.is_email)

    @staticmethod
    def is_email(value):
        return '@' in value


class PhoneField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=["", 0], **kwargs)
        self.validators.append(PhoneField.is_phone)

    @staticmethod
    def is_phone(value):
        if isinstance(value, (str, int)):
            value = str(value)
            return re.match(r'7\d{10}$', value) is not None
        return False


class DateField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(DateField.is_date)

    @staticmethod
    def is_date(value):
        try:
            date = datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            return False
        return True


class BirthDayField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(BirthDayField.is_birthday)

    @staticmethod
    def is_birthday(value):
        try:
            date = datetime.strptime(value, "%d.%m.%Y")
            cur_date = datetime.now()
            delta = cur_date - date
            if delta.days > 0 and delta.days < 70*365:
                return True
        except ValueError:
            pass
        return False


class GenderField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[None], **kwargs)
        self.validators.append(GenderField.is_gender)

    @staticmethod
    def is_gender(value):
        if isinstance(value, int) and value in GENDERS:
            return True
        return False


class ClientIDsField(Field):
    def __init__(self, **kwargs):
        super().__init__(null_values=[[]], **kwargs)
        self.validators.append(ClientIDsField.is_id)

    @staticmethod
    def is_id(value):
        if isinstance(value, list):
            return all(isinstance(v, int) for v in value)
        return False


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


class BaseRequest:
    def __init__(self, data=None):
        self.data = data
        self.errors = []
        self.pair_fields = []

    def __getattr__(self, attr):
        return self.data.get(attr)


    def is_valid(self):
        self.errors = []
        for field_name, field in self.fields.items():
            field_data = self.data.get(field_name)
            if not field.valid(field_data):
                self.errors.append("{}:{} invalid".format(field_name, field_data))
                logging.error("{}:{} invalid".format(field_name, field_data))
        if self.errors:
            return False

        if self.pair_fields:
            return self.check_pair()
        return not self.errors

    def check_pair(self):
        for f1, f2 in self.pair_fields:
            d1 = self.data.get(f1)
            d2 = self.data.get(f2)

            if (d1 is not None and d2 is not None and
                    d1 not in self.fields[f1].null_values and
                    d2 not in self.fields[f2].null_values):
                return True

        self.errors.append("The are not invalid pair fields")
        return False


class ClientsInterestsRequest(BaseRequest, metaclass=DeclarativeFields):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def get_response(self, ctx, store, args, is_admin=False):
        ctx["nclients"] = len(args.get('client_ids'))
        ids = args.get('client_ids')
        r = {i: scoring.get_interests(store, i) for i in ids}
        return r, OK


class OnlineScoreRequest(BaseRequest, metaclass=DeclarativeFields):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pair_fields = [("phone", "email"),
                            ("first_name", "last_name"),
                            ("gender", "birthday")]

    def get_response(self, ctx, store, args, is_admin=False):
        ctx["has"] = [f for f in args]
        score = 42
        if not is_admin:
            score = scoring.get_score(store, args.get('phone'),
                                      args.get('email'), args)
        return {"score": score}, OK


class MethodRequest(BaseRequest, metaclass=DeclarativeFields):
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

    req_body = request.get('body')
    req_args = req_body.get('arguments')
    req_method = req_body.get('method')

    req_base = MethodRequest(req_body)
    if not req_base.is_valid():
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    if not check_auth(req_base):
        return ERRORS[FORBIDDEN], FORBIDDEN

    try:
        req = router[req_method](req_args)
        if not req.is_valid():
            return ",".join(req.errors), INVALID_REQUEST
    except KeyError:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    return req.get_response(ctx, store, req_args, req_base.is_admin)


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
            request = json.loads(data_string.decode("utf-8") )
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
