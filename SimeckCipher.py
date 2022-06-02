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
    
def print_de(decrypted_message,message):
    print("Decrypted\t: ", (decrypted_message))
    print("Message_Dec\t: ",message)
    
def pencatatan1(i, date_now, plaintext, encrypted_message, encryption_periode):
    f = open('Speck.csv', 'a')
    f.write("Message ke-" + i + ";" + str(plaintext) + ";" + encrypted_message + ";"  + str(encryption_periode)+";" + date_now +  "\n")    
    
def getBinary(word):
    return int(binascii.hexlify(word), 16)
    
# Record the start time
start = timeit.default_timer()

key = 0x1FE2548B4A0D14DC7677770989767657

#key = 0x1f1e1d1c1b1a19181716151413121110
#key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908
# key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
cipher = SimeckCipher(master_key=key, key_size=128, block_size=64)
# cipher = SimonCipher(key, 128, 128, 'CBC', 0x123456789ABCDEF0)
message ={}

for i in range(1):
    # Creating random integer as paintext
    start1 = timeit.default_timer()    
    mess = 'dl:98765' #pesan max 8
    plaintext= int.from_bytes(mess.encode('utf-8'), byteorder='big', signed=False) #ubah ke decimal

    scale = 16
    binary = (bin((plaintext)).replace("0b","")).zfill(64) #ubah ke binary

    # Encrypting the plaintext
    encrypted_message = hex(cipher.encrypt(plaintext))
    date_now = str(datetime.now().timestamp())
    
    
    # Make the JSON data
    message['cipher'] = encrypted_message
    message['datetime'] = date_now
    stringify = json.dumps(message, indent=2)

    #Decrypting the ciphertext
    hexa = int(encrypted_message,16)
    decrypted_message1 = cipher.decrypt(hexa)
    decrypted_message = hex(decrypted_message1)

    #Str decrypted message
    message=bytes.fromhex(decrypted_message[2:]).decode('utf-8')

    # Displaying the Encryption data
    print_en(mess, plaintext, encrypted_message, date_now,binary)

    # Displaying the Encryption data
    print_de(decrypted_message,message)
    
    stop1 = timeit.default_timer()
    encryption_periode = stop1 - start1
    print("Waktu akumulasi : "+str(encryption_periode))
    
    # Make the data record
    # pencatatan1(str(i+1), date_now, plaintext, encrypted_message, encryption_periode)
    print()
    
# Record the finished time
stop = timeit.default_timer()
encryption_duration = stop - start
print("Waktu Total : "+str(encryption_duration))
