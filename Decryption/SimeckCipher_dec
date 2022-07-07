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
        # print hex(round_key), hex(left), hex(right)
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

def print_en(mess,plaintext, encrypted_message,date_now,binary):
    print("Message\t\t: ",mess)
    print("Plaintext\t: ", hex(plaintext))
    print("Plaintext binary: ",binary)
    print("Encrypted\t: ", str(encrypted_message)[2:])
    print("Length\t\t: ", len(str(encrypted_message)[2:]), "Bytes")
    print("Just published a message to topic Simon at "+ date_now)
    
def print_de(decrypted_message, message):
    print("Decrypted\t: ", (decrypted_message))
    print("Message_Dec\t: ",message)
    
def pencatatan(r, mess, plaintxt, encryption_periode,block_size,key_size,date_now):
    f = open('Simeck_dec.csv', 'a')
    f.write(";"+"Message ke-" + str(r+1) + ";" + str(len(mess))+ ";" + str(mess) + ";" +str(block_size)+ ";" + str(key_size) + ";"  +str(plaintxt) + ";"  + str(encryption_periode) +";"  + str(date_now)+";"+  "\n")
    
def getBinary(word):
    return int(binascii.hexlify(word), 16)

def decrypt_dt(cipher_txt):    
    # Record the start time
    #start = timeit.default_timer()
    
    key = 0x1FE2548B4A0D14DC #use when key_size=64
    # key = 0x1FE2548B4A0D14DC76777709 #use when key_size=96
    # key = 0x1FE2548B4A0D14DC7677770989767657 #use when key_size=128
    
    key_size=64
    block_size=32
    i=0

    cipher = SimeckCipher(master_key=key, key_size=key_size, block_size=block_size)
    message ={}

    for r in range(1):
        # Creating random integer as paintext
        start1 = timeit.default_timer()    
        mess = cipher_txt 
        dec2 = []
        dec=[]

        #fragmenting the message

        if block_size==32 :
            # Split the ciphertext
            c=8;i=0
            split_ct = [mess[i:i+c] for i in range(0, len(mess), c)]
            
            for x in split_ct:
                c_t= int(split_ct[i],16)
                i=i+1

                #decrypt ciphertext
                decrypted_message = cipher.decrypt(c_t) 
                decrypted_message1 = hex(decrypted_message)

                # Decode ciphertext
                message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
                dec.append(message) 
                date_now = str(datetime.now().timestamp())       
            a=""
            plaintext = a.join(dec)
            dec2.append(plaintext)
            
        if block_size==48 :
            # Split the ciphertext
            c=12;i=0
            split_ct = [mess[i:i+c] for i in range(0, len(mess), c)]
            
            for x in split_ct:
                c_t= int(split_ct[i],16)
                i=i+1

                #decrypt ciphertext
                decrypted_message = cipher.decrypt(c_t) 
                decrypted_message1 = hex(decrypted_message)

                # Decode ciphertext
                message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
                dec.append(message) 
                date_now = str(datetime.now().timestamp())       
            a=""
            plaintext = a.join(dec)
            dec2.append(plaintext)

        elif block_size==64 :
            # Split the ciphertext
            c=16;i=0
            split_ct = [mess[i:i+c] for i in range(0, len(mess), c)]
            
            for x in split_ct:
                c_t= int(split_ct[i],16)
                i=i+1

                #decrypt ciphertext
                decrypted_message = cipher.decrypt(c_t) 
                decrypted_message1 = hex(decrypted_message)

                # Decode ciphertext
                message=bytes.fromhex(decrypted_message1[2:]).decode('utf-8')
                dec.append(message) 
                date_now = str(datetime.now().timestamp())       
            a=""
            plaintext = a.join(dec)
            dec2.append(plaintext)
        
    b=""
    plaintxt=b.join(dec2)
    print("Plaintext: "+plaintxt)

    # print_en(mess, ciphertext)
    # print_de(plaintext)
            
    stop1 = timeit.default_timer()
    encryption_periode = stop1 - start1
    print("Waktu akumulasi : "+str(encryption_periode))

    # Make the data record
    pencatatan(r, mess,date_now, plaintxt, encryption_periode,block_size,key_size)    
    return(plaintxt)        
    
# # Record the finished time
# stop = timeit.default_timer()
# encryption_duration = stop - start
# print("Waktu Total : "+str(encryption_duration))
