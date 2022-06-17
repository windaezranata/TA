#!/usr/bin/env python
from operator import length_hint
from random import randint
import timeit
from time import sleep
from collections import deque
from datetime import datetime
import json
import binascii


NUM_ROUNDS = {
    # (block_size, key_size): num_rounds
    (32, 64): 32,
    (48, 96): 36,
    (64, 128): 44,
}


def get_sequence(num_rounds):
    if num_rounds < 40:
        states = [1] * 5
    else:
        states = [1] * 6

    for i in range(num_rounds - 5):
        if num_rounds < 40:
            feedback = states[i + 2] ^ states[i]
        else:
            feedback = states[i + 1] ^ states[i]
        states.append(feedback)

    return tuple(states)


class SimeckCipher:
    def __init__(self, block_size, key_size, master_key):
        assert (block_size, key_size) in NUM_ROUNDS
        assert 0 <= master_key < (1 << key_size)
        self._block_size = block_size
        self._key_size = key_size
        self._word_size = int(block_size / 2)
        self._num_rounds = NUM_ROUNDS[(block_size, key_size)]
        self._sequence = get_sequence(self._num_rounds)
        self._modulus = 1 << self._word_size
        self.change_key(master_key)

    def _LROT(self, x, r):
        assert 0 <= x < self._modulus
        res = (x << r) % self._modulus
        res |= x >> (self._word_size - r)
        return res

    def _round(self, round_key, left, right,decrypt):
        assert 0 <= round_key < self._modulus
        assert 0 <= left <self._modulus
        assert 0 <= right < self._modulus
        if decrypt:
            temp =right
            right = left ^ (right & self._LROT(right,5)) ^ self._LROT(right, 1) ^ round_key
            left=temp
        else:
            temp = left
            left = right ^ (left & self._LROT(left, 5)) \
            ^ self._LROT(left, 1) ^ round_key
            right = temp

        return left, right

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self._key_size)
        states = []
        for i in range(int(self._key_size / self._word_size)):
            states.append(master_key % self._modulus)
            master_key >>= self._word_size

        constant = self._modulus - 4
        round_keys = []
        for i in range(self._num_rounds):
            round_keys.append(states[0])
            left, right = states[1], states[0]
            left, right = self._round(constant ^ self._sequence[i],
                                      left, right,False)
            states.append(left)
            states.pop(0)
            states[0] = right

        self.__round_keys = tuple(round_keys)

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self._block_size)
        left = plaintext >> self._word_size
        right = plaintext % self._modulus

        for idx in range(self._num_rounds):
            left, right = self._round(self.__round_keys[idx],
                                      left, right, False)

        ciphertext = (left << self._word_size) | right
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self._block_size)
        left = ciphertext >> self._word_size
        right = ciphertext % self._modulus

        for idx in range(self._num_rounds - 1, -1, -1):
            left, right = self._round(self.__round_keys[idx], left, right, True)

        plaintext = (left << self._word_size) | right
        return plaintext

def print_en(mess, ciphertext,):
    print("Message\t\t: ",mess)
    print("Block Size\t: ", block_size)
    print("Key Size\t: ",key_size)
    print("Ciphertext\t: ", ciphertext, "\n")
    print("Length\t\t: ", len(ciphertext), "Bytes")
    # print("Just published a message to topic Simon at "+ date_now, "\n")
    
def print_de(plaintext):
    print("Decrypt Message\t: ",plaintext)

    
def pencatatan1(r, date_now, mess, ciphertext, encryption_periode):
    f = open('Simon.csv', 'a')
    f.write("Message ke-" + str(r+1) + ";" + str(mess) + ";" + str(ciphertext) + ";"  + str(encryption_periode)+";" + date_now +  "\n")    
 
def getBinary(word):
    return int(binascii.hexlify(word), 16)
    
# Record the start time
start = timeit.default_timer()
# key = 0x1FE2548B4A0D14DC # max 16 kar. utk block size 32
key = 0x1FE2548B4A0D14DC7677770989767657  

#key = 0x1f1e1d1c1b1a19181716151413121110
#key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908
# key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
key_size=128
block_size=64

cipher = SimeckCipher(master_key=key, key_size=key_size, block_size=block_size)
message ={}

for r in range(1):
    # Creating random integer as paintext
    start1 = timeit.default_timer()    
    mess = 'dl:98765435678va:2.213rf:123.45Tm:100.00Hm:872798.99' 
    enc = []
    dec=[]
    i=0
    #fragmenting the message

    #fragmenting the message

    if block_size==32 :
        n = 4	# every 6 characters
        split_mess = [mess[i:i+n] for i in range(0, len(mess), n)]
        
        for x in split_mess:
            plaintext= int.from_bytes(split_mess[i].encode('utf-8'), byteorder='big', signed=False) #ubah ke decimal
            i=i+1
            scale = 16
            # binary = (bin((plaintext)).replace("0b","")).zfill(64) #ubah ke binary
            
            # Encrypting the plaintext
            encrypted_message = hex(cipher.encrypt(plaintext))
            ct=(encrypted_message[2:].zfill(8))
            enc.append(ct)
            
            date_now = str(datetime.now().timestamp())
        a=""
        ciphertext = a.join(enc) #ciphertext
        
        # Split the ciphertext
        c=8;i=0
        split_ct = [ciphertext[i:i+c] for i in range(0, len(ciphertext), c)]
        
        for x in split_ct:
            c_t= int(split_ct[i],16)
            i=i+1

            #decrypt ciphertext
            decrypted_message = cipher.decrypt(c_t) 
            decrypted_message1 = hex(decrypted_message)

            # Decode ciphertext
            message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
            dec.append(message)        
        b=""
        plaintext = b.join(dec)
        
    if block_size==48 :
        n = 6	# every 6 characters
        split_mess = [mess[i:i+n] for i in range(0, len(mess), n)]
        
        for x in split_mess:
            plaintext= int.from_bytes(split_mess[i].encode('utf-8'), byteorder='big', signed=False) #ubah ke decimal
            i=i+1
            scale = 16
            # binary = (bin((plaintext)).replace("0b","")).zfill(64) #ubah ke binary
            
            # Encrypting the plaintext
            encrypted_message = hex(cipher.encrypt(plaintext))
            ct=(encrypted_message[2:].zfill(12))
            enc.append(ct)
            
            date_now = str(datetime.now().timestamp())
        a=""
        ciphertext = a.join(enc) #ciphertext
        
        # Split the ciphertext
        c=12;i=0
        split_ct = [ciphertext[i:i+c] for i in range(0, len(ciphertext), c)]
        
        for x in split_ct:
            c_t= int(split_ct[i],16)
            i=i+1

            #decrypt ciphertext
            decrypted_message = cipher.decrypt(c_t) 
            decrypted_message1 = hex(decrypted_message)

            # Decode ciphertext
            message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
            dec.append(message)        
        b=""
        plaintext = b.join(dec)

    elif block_size==64 :
        n = 8	# every 6 characters
        split_mess = [mess[i:i+n] for i in range(0, len(mess), n)]
        
        for x in split_mess:
            plaintext= int.from_bytes(split_mess[i].encode('utf-8'), byteorder='big', signed=False) #ubah ke decimal
            i=i+1
            scale = 16
            # binary = (bin((plaintext)).replace("0b","")).zfill(64) #ubah ke binary
            
            # Encrypting the plaintext
            encrypted_message = hex(cipher.encrypt(plaintext))
            ct=(encrypted_message[2:].zfill(16))
            enc.append(ct)
            
            date_now = str(datetime.now().timestamp())
        a=""
        ciphertext = a.join(enc) #ciphertext
        
        # Split the ciphertext
        c=16;i=0
        split_ct = [ciphertext[i:i+c] for i in range(0, len(ciphertext), c)]
        
        for x in split_ct:
            c_t= int(split_ct[i],16)
            i=i+1

            #decrypt ciphertext
            decrypted_message = cipher.decrypt(c_t) 
            decrypted_message1 = hex(decrypted_message)

            # Decode ciphertext
            message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
            dec.append(message)        
        b=""
        plaintext = b.join(dec)
    
    print_en(mess, ciphertext)
    print_de(plaintext)
    
    
    stop1 = timeit.default_timer()
    encryption_periode = stop1 - start1
    print("Waktu akumulasi : "+str(encryption_periode))
    
    # Make the data record
    # pencatatan1(r, date_now, mess, ciphertext, encryption_periode)    
    print()
    
# # Record the finished time
# stop = timeit.default_timer()
# encryption_duration = stop - start
# print("Waktu Total : "+str(encryption_duration))
