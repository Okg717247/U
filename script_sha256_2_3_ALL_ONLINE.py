# Changed and edited by @Alpha Century

import os, hashlib, base58, ecdsa
from bitcoin import *
import colorama
from colorama import Fore, Back, Style
colorama.init()
import random
from datetime import datetime
import secrets
from secrets import token_hex
from base64 import b64encode
import multiprocessing
import requests
#import winsound
import bech32
import binascii
secretsGenerator = secrets.SystemRandom()
import Crypto.Random.random as rand
import secrets
secretsGenerator = secrets.SystemRandom()
import Crypto
from Crypto import Random
import sys
from Crypto.Hash import SHA256
import hashlib
import random as rand
from secrets import randbelow
from random import SystemRandom
import eth_keys
from eth_keys import keys
import time

frequency = 2500  # Set Frequency To 2500 Hertz
duration = 2000  # Set Duration To 1000 ms == 1 second


#file1=open("SCRIPT_SHA256_all_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
file2=open("SCRIPT_SHA256_HEXA_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file3=open("SCRIPT_SHA256_WIFu_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file4=open("SCRIPT_SHA256_WIFc_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file5=open("SCRIPT_SHA256_p2pkhC_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file6=open("SCRIPT_SHA256_p2pkhU_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file7=open("SCRIPT_SHA256_p2shC_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file8=open("SCRIPT_SHA256_p2shU_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file9=open("SCRIPT_SHA256_bech32C_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
#file10=open("SCRIPT_SHA256_bech32U_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")
file11=open("SCRIPT_SHA256_ETHER_"+time.strftime("%Y-%m-%d-%H-%M")+".txt","a")



def ripemd160(x):
	d = hashlib.new('ripemd160')
	d.update(x)
	return d

def hexPrvToWif(hexPrv, compressed):
	suffix = ""
	if compressed:
		suffix = "01"
	fullkey = '80' + hexPrv + suffix
	sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
	sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
	return base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8])).decode()

def wifToPrvHex(wif) :
	byte_str = binascii.hexlify(base58.b58decode(wif))
	byte_str_drop_last_4bytes = byte_str[0:-8]
	byte_str_drop_first_byte = byte_str_drop_last_4bytes[2:].decode()
	return byte_str_drop_first_byte if len(byte_str_drop_first_byte) == 64 else byte_str_drop_first_byte[:-2]

def prvToPub(hexPrv, compressed):
	sk = ecdsa.SigningKey.from_string(binascii.unhexlify(hexPrv.encode()), curve=ecdsa.SECP256k1)
	vk = sk.get_verifying_key()
	if compressed:
		from ecdsa.util import number_to_string
		order = vk.pubkey.order
		x_str = binascii.hexlify(number_to_string(vk.pubkey.point.x(), order))
		sign = '02' if vk.pubkey.point.y() % 2 == 0 else '03'
		return (sign.encode() + x_str).decode()
	return '04' + binascii.hexlify(vk.to_string()).decode()

def p2pkh_address(pub): # starts with 1
	hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(pub)).digest()).digest()
	publ_addr_a = b"\x00" + hash160
	checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
	return base58.b58encode(publ_addr_a + checksum).decode()

def p2sh_address(pub): # starts with 3
	hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(pub)).digest()).digest()
	publ_addr_a = b'\x00\x14' + hash160 # bytes.fromhex("0014")
	script = ripemd160(hashlib.sha256(publ_addr_a).digest()).digest()
	return base58.b58encode_check(b"\x05" + script).decode()

def bech32_address(pub): # starts with bc1
	keyhash = hashlib.new("ripemd160", hashlib.sha256(binascii.unhexlify(pub)).digest()).digest()
	return bech32.encode('bc', 0, keyhash)


low  = 0x0000000000000000000000000000000000000000000000008000000000000000
high = 0xfffffffffffffffffffffffffffffffebaaedce6af48a02bbfd25e8cd036413b
#high = 0x000000000000000000000000000000000000000000000000ffffffffffffffff

def main():
 while True:
    #random.seed(datetime.now())
    #ran = random.randrange(low,high,1)
    #ran = secretsGenerator.getrandbits(128)
    #ran = secrets.randbits(250)
    #ran = random.randrange(2**64)
    #ran = rand.getrandbits(256) 
    #ran = Crypto.Random.random.randrange(low,high,1)
    #ran = Crypto.Random.random.randint(9223372036854775808,18446744073709551615)
    #ran = rand.getrandbits(256)
    #ran = secretsGenerator.randrange(8993229949524465672,8993229949524482056)
    #ran = secretsGenerator.getrandbits(256)
    #ran = Crypto.Random.random.getrandbits(256)
    #ran = random.SystemRandom().getrandbits(256)
    #ran = secrets.SystemRandom().getrandbits(196)
    #ran = secrets.SystemRandom().randrange(2**196)
    #ran = SystemRandom().randrange(2**256)
    #ran = (secrets.token_hex(32))
    #ran = binascii.hexlify(os.urandom(32)).decode()
    #ran = binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
    #ran = hashlib.sha256(str(random.getrandbits(256)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(1024)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(1024)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(512)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(512)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(256)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(196)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(196)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(128)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(128)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(64)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(64)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(1024)).encode('UTF-16LE')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(1024)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(512)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(512)).encode('UTF-8')).hexdigest()
    ##ran = hashlib.sha256(str(random.getrandbits(32)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(512)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(os.urandom(252)).hexdigest()
    #ran = hashlib.sha256(os.urandom(1024)).hexdigest()
    #ran = secrets.token_hex(nbytes=32)
    #ran = hashlib.sha256(str(secrets.token_hex(32)).encode('utf-8')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(196)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(196)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(128)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(128)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(64)).encode('UTF-8')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(64)).encode('UTF-8')).hexdigest()
    #ran = binascii.hexlify(os.urandom(32)).decode('utf-8')
    #ran = binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
    #ran = hashlib.sha256(str(random.getrandbits(1024)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(1024)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(512)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(512)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(256)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(196)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(196)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(128)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(128)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha256(str(random.getrandbits(64)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(64)).encode('Windows-1252')).hexdigest()
    #ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('BIG5+')).hexdigest()
    #ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('UTF-16LE')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('BIG5')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('BIG5')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('GB2312')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('GB2312')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('ASCII')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('ASCII')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('ANSI')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('ANSI')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('BIG5+')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('BIG5+')).hexdigest()
    ####ran = hashlib.sha256(str(random.getrandbits(256)).encode('ISO8859')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.getrandbits(256)).encode('ISO8859')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('UTF-8')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('UTF-8')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('UTF-16LE')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('UTF-16LE')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('Windows-1252')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('Windows-1252')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('BIG5')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('BIG5')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('BIG5+')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('BIG5+')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ANSI')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ANSI')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ASCII')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ASCII')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('GB2312')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('GB2312')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ISO8859')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('ISO8859')).hexdigest()
    ####ran = hashlib.sha256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('Macintosh')).hexdigest()
    ####ran = hashlib.sha3_256(str(random.randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)).encode('Macintosh')).hexdigest()
    #ran = hashlib.sha256(str(random.randrange(1764613997892457936451903530140172288,115792089237316195423570985008687907852837564279074904)).encode('GB2312')).hexdigest()
    ran = hashlib.sha3_256(str(random.randrange(664613997892457936451903530140172288,1329227995784915872903807060280344575)).encode('UTF-8')).hexdigest() # Works!

    myhex = ran
    hexPrv = myhex
    Upub = prvToPub(hexPrv, False)
    Cpub = prvToPub(hexPrv, True)
    addr5 = bech32_address(Upub)  #Segwit (bech32) uncompressed address
    private_key = myhex[:64]
    private_key_bytes = bytes.fromhex(private_key)
    public_key_hex = keys.PrivateKey(private_key_bytes).public_key
    public_key_bytes = bytes.fromhex(str(public_key_hex)[2:])
    ether = keys.PublicKey(public_key_bytes).to_address()			#Eth address
    addr7 = p2sh_address(Upub)
       
  
    
    response1 = requests.get('https://blockchain.info/q/getreceivedbyaddress/'+p2pkh_address(Cpub))
    #response1 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+p2pkh_address(Cpub))
    balance1 = 0
    balance1 = response1.json()/100000000
    #balance1 = response1.json()["confirmed_balance"]/100000000
    
    response2 = requests.get('https://blockchain.info/q/getreceivedbyaddress/'+p2pkh_address(Upub))
    #response2 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+p2pkh_address(Upub))
    balance2 = 0
    balance2 = response2.json()/100000000
    #balance2 = response2.json()["confirmed_balance"]/100000000
    
    response3 = requests.get('https://blockchain.info/q/getreceivedbyaddress/'+p2sh_address(Cpub))
    #response3 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+p2sh_address(Cpub))
    balance3 = 0
    balance3 = response3.json()/100000000
    #balance3 = response3.json()["confirmed_balance"]/100000000

    response4 = requests.get('https://blockchain.info/q/getreceivedbyaddress/'+p2sh_address(Upub))
    #response4 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+p2sh_address(Upub))
    balance4 = 0
    balance4 = response4.json()/100000000
    #balance4 = response4.json()["confirmed_balance"]/100000000
    
    response5 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+ bech32_address(Cpub))
    balance5 = 0
    balance5 = response5.json()["confirmed_balance"]/100000000
    
    response6 = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+ bech32_address(Upub))
    balance6 = 0
    balance6 = response6.json()["confirmed_balance"]/100000000
    
    
    
    if (balance1 > 0):
        print(Fore.BLUE + "KEY!","COMPRESSED BTC:",p2pkh_address(Cpub),hexPrv + "\n\n" + "BTC:",balance1)
        s1 = hexPrv
        s2 = p2pkh_address(Cpub)
        s3 = str(balance1)
        f=open("FOUND BTC.txt","a")
        f.write("COMPRESSED BTC: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n") 
        f.close()
        #winsound.Beep(frequency, duration)
        
    
    if (balance2 > 0):
        print(Fore.BLUE + "KEY!","UNCOMPRESSED BTC:",p2pkh_address(Upub),hexPrv + "\n\n" + "BTC:",balance2)
        s1 = hexPrv
        s2 = p2pkh_address(Upub)
        s3 = str(balance2)
        f=open("FOUND BTC.txt","a")
        f.write("UNCOMPRESSED BTC: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n") 
        f.close()
        #winsound.Beep(frequency, duration)
        
    if (balance3 > 0):
        print(Fore.BLUE + "KEY!","P2SH:",p2sh_address(Cpub),hexPrv + "\n\n" + "BTC:",balance3)
        s1 = hexPrv
        s2 = p2sh_address(Cpub)
        s3 = str(balance3)
        f=open("FOUND BTC.txt","a")
        f.write("P2SHc: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n")  
        f.close()
        #winsound.Beep(frequency, duration)

    if (balance4 > 0):
        print(Fore.BLUE + "KEY!","P2SH:",p2sh_address(Upub),hexPrv + "\n\n" + "BTC:",balance4)
        s1 = hexPrv
        s2 = p2sh_address(Upub)
        s3 = str(balance4)
        f=open("FOUND BTC.txt","a")
        f.write("P2SHu: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n")  
        f.close()
        #winsound.Beep(frequency, duration)
        
    if (balance5 > 0):
        print(Fore.BLUE + "KEY!","bech32c:",bech32_address(Cpub),hexPrv + "\n\n" + "BTC:",balance5)
        s1 = hexPrv
        s2 = bech32_address(Cpub)
        s3 = str(balance5)
        f=open("FOUND BTC.txt","a")
        f.write("bech32c: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n")  
        f.close()
        #winsound.Beep(frequency, duration)

    if (balance6 > 0):
        print(Fore.BLUE + "KEY!","bech32u:",bech32_address(Upub),hexPrv + "\n\n" + "BTC:",balance6)
        s1 = hexPrv
        s2 = bech32_address(Upub)
        s3 = str(balance6)
        f=open("FOUND BTC.txt","a")
        f.write("bech32c: " + s2 + "\n" + "hex: " + s1 + "\n\n" + "BTC:" + s3 + "\n\n")  
        f.close()
        #winsound.Beep(frequency, duration)
        

        
        
    print("=========================== [ BITCOIN ADDRESS ] ===========================")
    print(Fore.GREEN +"COMPRESSED:",p2pkh_address(Cpub) + "\n" + "UNCOMPRESSED:",p2pkh_address(Upub) + "\n" + "P2SHc:",p2sh_address(Cpub))
    print(Fore.GREEN +"P2SHu:",p2sh_address(Upub) + "\n" + "bech32c:",bech32_address(Cpub) + "\n" + "bech32u:",bech32_address(Upub))
    print("======================= [ BITCOIN PRIVATE KEYS ] =======================")
    print("hex:",hexPrv)
    print("Compressed Private Key  : ", hexPrvToWif(hexPrv, True))
    print("Uncompressed Private Key: ", hexPrvToWif(hexPrv, False))
    print("======================= [ BITCOIN BALANCE CHECK ] =======================")
    print(Fore.RED +"COMPRESSED   BTC:"+ str(balance1))
    print(Fore.RED +"UNCOMPRESSED BTC:"+ str(balance2))
    print(Fore.RED +"P2SHc:"+ str(balance3))
    print(Fore.RED +"P2SHu:"+ str(balance4))
    print(Fore.RED +"bech32c:"+ str(balance5))
    print(Fore.RED +"bech32u:"+ str(balance6))
    #print(hexPrv+" "+ether+"\n") #addr6


    file1.write(hexPrv+" "+hexPrvToWif(hexPrv, True)+" "+hexPrvToWif(hexPrv, False)+" "+p2pkh_address(Cpub)+" "+p2pkh_address(Upub)+" "+p2sh_address(Cpub)+" "+p2sh_address(Upub)+" "+bech32_address(Cpub)+" "+bech32_address(Upub)+" "+ether+"\n")
    file2.write(hexPrv+"\n")
    file3.write(hexPrvToWif(hexPrv, True)+"\n")
    file4.write(hexPrvToWif(hexPrv, False)+"\n")    
    file5.write(p2pkh_address(Cpub)+"\n")
    file6.write(p2pkh_address(Upub)+"\n")
    file7.write(p2sh_address(Cpub)+"\n")
    file8.write(p2sh_address(Upub)+"\n") # addr7
    file9.write(bech32_address(Cpub)+"\n")
    file10.write(bech32_address(Upub)+"\n") # addr5
    file11.write(ether+"\n") # addr6   
		
		
if __name__ == '__main__':
    thread = int(4)
    for cpu in range(thread):
        multiprocessing.Process(target = main).start()
