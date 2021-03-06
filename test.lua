local hkdf = require'lhkdf'

local salt = "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99"
local cid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08"
local initial_secret = hkdf.extract(salt, cid)
local expected_initial_secret = "\x1e\x7e\x77\x64\x52\x97\x15\xb1\xe0\xdd\xc8\xe9\x75\x3c\x61" ..
                                "\x57\x67\x69\x60\x51\x87\x79\x3e\xd3\x66\xf8\xbb\xf8\xc9\xe9\x86\xeb"
assert(expected_initial_secret == initial_secret)

local client_in = "\x00\x20\x0f\x74\x6c\x73\x31\x33\x20\x63\x6c\x69\x65\x6e\x74\x20\x69\x6e\x00"
local client_initial_secret = hkdf.expand(initial_secret, client_in, 32)
local expected_client_initial_secret = "\x00\x88\x11\x92\x88\xf1\xd8\x66\x73\x3c\xee\xed\x15\xff\x9d\x50" ..
                                       "\x90\x2c\xf8\x29\x52\xee\xe2\x7e\x9d\x4d\x49\x18\xea\x37\x1d\x87"
assert(client_initial_secret == expected_client_initial_secret)

local quic_iv = "\x00\x0c\x0d\x74\x6c\x73\x31\x33\x20\x71\x75\x69\x63\x20\x69\x76\x00"
local client_iv = hkdf.expand(client_initial_secret, quic_iv, 12)
local expected_client_iv = "\x6b\x26\x11\x4b\x9c\xba\x2b\x63\xa9\xe8\xdd\x4f"
assert(client_iv == expected_client_iv)

local quic_key = "\x00\x10\x0e\x74\x6c\x73\x31\x33\x20\x71\x75\x69\x63\x20\x6b\x65\x79\x00"
local client_key = hkdf.expand(client_initial_secret, quic_key, 16)
local expected_client_key = "\x17\x52\x57\xa3\x1e\xb0\x9d\xea\x93\x66\xd8\xbb\x79\xad\x80\xba"
assert(client_key == expected_client_key)

local quic_hp = "\x00\x10\x0d\x74\x6c\x73\x31\x33\x20\x71\x75\x69\x63\x20\x68\x70\x00"
local client_hp = hkdf.expand(client_initial_secret, quic_hp, 16)
local expected_client_hp = "\x9d\xdd\x12\xc9\x94\xc0\x69\x8b\x89\x37\x4a\x9c\x07\x7a\x30\x77"
assert(client_hp == expected_client_hp)
