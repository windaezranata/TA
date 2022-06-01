#!/usr/bin/env python
from operator import length_hint
from random import randint
import timeit
from time import sleep
from collections import deque
from datetime import datetime
import json

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


class Simeck:
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

def print_test_vector_en(block_size, key_size, key, plain, cipher):
    print ('Simeck  : ', block_size, key_size)
    print ('key     : ', hex(key)[2:].rstrip('L').zfill(int(key_size / 4)))
    print ('plaintext   :', hex(plain)[2:].rstrip('L').zfill(int(block_size / 4)))
    print ('ciphertext  : ', hex(cipher)[2:].rstrip('L').zfill(int(block_size / 4)))
   #print("\n")

def print_test_vector_de(block_size, key_size, key, plain, cipher):
    print ('Simeck      : ', block_size, key_size)
    print ('key         : ', hex(key)[2:].rstrip('L').zfill(int(key_size / 4)))
    print ('ciphertext  :', hex(plain)[2:].rstrip('L').zfill(int(block_size / 4)))
    print ('plaintext   : ', hex(cipher)[2:].rstrip('L').zfill(int(block_size / 4)))
   #print("\n")


def print_en(plaintext, encrypted_message,date_now,binary):
    print("Plaintext\t: ", plaintext)
    print("Plaintext binary: ",binary)
    print("Encrypted\t: ", str(encrypted_message)[2:])
    print("Length\t\t: ", len(str(encrypted_message)[2:]), "Bytes")
    print("Just published a message to topic Simeck at "+ date_now)

def print_de(decrypted_message):
    print("Decrypted\t: ", decrypted_message)
# def pencatatan(i, date_now, plaintext, encrypted_message):
#     f = open('Publish_Simon.csv', 'a')
#     f.write("Message ke-" + i + ";" + str(plaintext) + ";" + encrypted_message + ";" + date_now + "\n")    

def pencatatan1(i, date_now, plaintext, encrypted_message, encryption_periode):
    f = open('Simeck.csv', 'a')
    f.write("Message ke-" + i + ";" + str(plaintext) + ";" + encrypted_message + ";"  + str(encryption_periode)+";" + date_now +  "\n")    
    
# Record the start time
start = timeit.default_timer()

key = 0x1FE2548B4A0D14DC7677770989767657

# key_len=str(hex(key))[2:]
# print("key length: ",len(key_len))
#key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908
# key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
cipher = Simeck(block_size=64, key_size=128,master_key=key)
message ={}

for i in range(10):
    # Creating random integer as paintext
    start1 = timeit.default_timer()    
    plaintext = randint (0,0xFFFFFFFFFFFFFFFF)
    # plaintext = 14
    scale = 16
    binary = (bin((plaintext)).replace("0b","")).zfill(64)
    # print("Plaintext binary: ", str(res))

    # Encrypting the plaintext
    encrypted_message = (hex(cipher.encrypt(plaintext)))
    date_now = str(datetime.now().timestamp())
    
    
    # Make the JSON data
    message['cipher'] = encrypted_message
    message['datetime'] = date_now
    stringify = json.dumps(message, indent=2)

    #Decrypting the ciphertext
    hexa = int(encrypted_message,16)
    decrypted_message = cipher.decrypt(hexa)

    # Displaying the Encryption data
    print_en(plaintext, encrypted_message, date_now,binary)

    # Displaying the Encryption data
    print_de(decrypted_message)
    
    stop1 = timeit.default_timer()
    encryption_periode = stop1 - start1
    print("Waktu akumulasi : "+str(encryption_periode))
    print()
    # Make the data record
    # pencatatan1(str(i+1), date_now, plaintext, encrypted_message, encryption_periode)

# Record the finished time
stop = timeit.default_timer()
encryption_duration = stop - start
print("Waktu Total : "+str(encryption_duration))


