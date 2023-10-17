from ctypes import *

dll = CDLL("../../target/liblbv.so")
isolate = c_void_p()
isolatethread = c_void_p()
dll.graal_create_isolate(None, byref(isolate), byref(isolatethread))
dll.up.restype = c_long
result = dll.up(isolatethread, c_char_p(bytes("""
    [Interface]
    PrivateKey = SNG/stVFz0fyoa7LJU4/kMmzg5vmgTFR3GNu2o5q3WQ=
    Address = 172.16.11.1
    DNS = 172.16.1.101,logonbox.local

    [Peer]
    PublicKey = OW9Im40fr3Lq6knUMy/mObQ2jr332ESXulZM9OannyI=
    Endpoint = 3.251.31.162:51820
    PersistentKeepalive = 30
    AllowedIPs = 172.16.11.0/24, 172.16.1.0/24
    """, "utf8")), 0, 0)
