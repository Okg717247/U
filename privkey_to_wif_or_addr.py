from bitcoin import *

f = open('test.txt', "r")
privates = []
linia = f.readline()

while linia != "":
    linia = linia[0 :-1]
    privates.append (linia)
    linia = f.readline()

f.close()

for priv in privates:
    pub = privtopub(priv)
    addr = pubtoaddr(pub)
    wif = encode_privkey(priv, 'wif')
    pub1 = encode_pubkey(privtopub(priv), "bin_compressed")
    addr1 = pubtoaddr(pub1)
    wif1 = encode_privkey(priv, 'wif_compressed')
    print (addr, wif)
    print (addr1, wif1)
