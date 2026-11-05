"""Native PAM probe for disposable acceptance. Secrets are accepted only on stdin."""

import ctypes as c
import json
import os
import pwd
import sys


class Message(c.Structure):
    _fields_ = [("style", c.c_int), ("message", c.c_char_p)]


class Response(c.Structure):
    _fields_ = [("response", c.c_void_p), ("code", c.c_int)]


Callback = c.CFUNCTYPE(
    c.c_int, c.c_int, c.POINTER(c.POINTER(Message)), c.POINTER(c.POINTER(Response)), c.c_void_p
)


class Conversation(c.Structure):
    _fields_ = [("callback", Callback), ("data", c.c_void_p)]


def probe(request):
    pam = c.CDLL("libpam.so.0")
    libc = c.CDLL(None)
    libc.calloc.argtypes = [c.c_size_t, c.c_size_t]
    libc.calloc.restype = c.c_void_p
    libc.strdup.argtypes = [c.c_char_p]
    libc.strdup.restype = c.c_void_p

    @Callback
    def converse(count, messages, responses, data):
        memory = libc.calloc(count, c.sizeof(Response))
        answers = c.cast(memory, c.POINTER(Response))
        for index in range(count):
            item = messages[index].contents
            if item.style in (1, 2):
                answer = request.get("password", "")
                answers[index].response = libc.strdup(answer.encode())
            elif item.style not in (3, 4):
                return 19
        responses[0] = answers
        return 0

    conversation = Conversation(converse, None)
    handle = c.c_void_p()
    pam.pam_start.argtypes = [
        c.c_char_p,
        c.c_char_p,
        c.POINTER(Conversation),
        c.POINTER(c.c_void_p),
    ]
    pam.pam_end.argtypes = [c.c_void_p, c.c_int]
    pam.pam_set_item.argtypes = [c.c_void_p, c.c_int, c.c_void_p]
    for name in ("pam_authenticate", "pam_acct_mgmt"):
        getattr(pam, name).argtypes = [c.c_void_p, c.c_int]
        getattr(pam, name).restype = c.c_int
    code = pam.pam_start(
        request["service"].encode(),
        request["user"].encode(),
        c.byref(conversation),
        c.byref(handle),
    )
    if code:
        return {"start": code}
    pam.pam_set_item(handle, 8, c.c_char_p(pwd.getpwuid(os.getuid()).pw_name.encode()))
    operation = request["operation"]
    try:
        if operation == "account":
            code = pam.pam_acct_mgmt(handle, 0)
            return {"account": code}
        code = pam.pam_authenticate(handle, 0)
        result = {"authentication": code}
        if code == 0:
            code = pam.pam_acct_mgmt(handle, 0)
            result["account"] = code
        return result
    finally:
        pam.pam_end(handle, code)


if __name__ == "__main__":
    print(json.dumps(probe(json.load(sys.stdin))))
