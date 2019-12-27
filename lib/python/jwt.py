#!/usr/bin/env python3

import requests
import sys
import json
import binascii


class JWT():
    def __init__(self, token):
        self.token = token

    def add_padding(self, s):
        s = s + "=" * (len(s) % 4)

    def b64_decode(self, base64_str):
        if len(base64_str) > 4:
            base64_str = base64_str + "=" * (4 - (len(base64_str) % 4))
        else:
            base64_str = base64_str + "=" * (len(base64_str) % 4)

        return binascii.a2b_base64(base64_str.encode("ascii", errors="ignore")).strip(b"=").decode("ascii", errors="ignore")

    def b64_encode(self, s):
        s = s.replace(" ", "")
        return binascii.b2a_base64(s.encode("ascii", errors="ignore")).strip(b"=").decode("ascii")

    def field_update(self, field, change_dict):
        field = self.b64_decode(field)

        json_dict = json.loads(field)
        json_dict.update(change_dict)

        return self.b64_encode(json.dumps(json_dict)).strip(" \n=")

    def modify(self, field, change_dict, signature=None):
        len_sig_base64 = 342
        header = self.token.split(".")[0]
        payload = self.token.split(".")[1]
        if not signature:
            signature = self.token.split(".")[2]

        if field == "header":
            header = self.field_update(header, change_dict)
            #print("[+] - New header: {}".format(header))
        elif field == "payload":
            payload = self.field_update(payload, change_dict)
            print("[+] - New payload: {}".format(payload))
        else:
            print("[E] - Invalid modification target")
            sys.exit(1)

        return "{}.{}.{}".format(header, payload, signature)
