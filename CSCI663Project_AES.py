######## INFORMATION ############################################################
#                                                                               #
# CSCI663G A                                                                    #
# Fall 2023                                                                     #
# Instructor: Dr. Hong Zeng                                                     #
# Contributor to this file: José Nazareno Torres Ambrósio                       #
#                                                                               #
#################################################################################

import sys
import hashlib
from random import randint
from copy import copy
from getpass import getpass

ROUND_CONSTANT = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
]

SUBSTITUTION_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

SUBSTITUTION_BOX_INVERSE = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]


# returns a replica of the word shifted n bytes (characters) to the left
def rotate_word_bytes(word, n):
    return word[n:]+word[0:n]


# iterate over each one of the "virtual" rows from the state table shifting their bytes
# to the left by the proper offset
def shift_rows(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate_word_bytes(state[i*4:i*4+4], i)


# iterate over each one of the "virtual" rows from the state table shifting their bytes
# to the right by the proper offset
def shift_rows_inverse(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate_word_bytes(state[i*4:i*4+4], -i)


# receives a four-byte word and an iteration number
# then applies it bytes rotation, bytes substitution
# and return the new word
def key_schedule(word, i):
    new_word = []

    # rotates the word one byte to the left
    word = rotate_word_bytes(word, 1)

    # applies bytes substitution on all word's bytes
    for byte in word:
        new_word.append(SUBSTITUTION_BOX[byte])

    # XOR the ROUND_CONSTANT[i] transformation's output with the word's first part
    new_word[0] = new_word[0] ^ ROUND_CONSTANT[i]
    return new_word


# expands the 256-bit cipher_key into 240 bytes of key
# from which each round key is obtained
def expandKey(cipher_key):
    cipher_key_size = len(cipher_key)
    assert cipher_key_size == 32

    current_size = 0

    # expanded_key list
    expanded_key = []

    round_constant_index = 1

    # temporary list to save four bytes at a time
    expanded_key_next_4_bytes = [0, 0, 0, 0]

    # the expanded_key saves a copy of the cipher_key's first 32 bytes
    for i in range(cipher_key_size):
        expanded_key.append(cipher_key[i])
    current_size += cipher_key_size

    # generate and fill the expanded_key with the remaining bytes until it gets to a 240 bytes key size
    while current_size < 240:
        # assigns previous expanded_key's four bytes to the temporary storage expanded_key_next_4_bytes
        for i in range(4):
            expanded_key_next_4_bytes[i] = expanded_key[(current_size - 4) + i]
            print("expanded_key_next_4_bytes inicial",
                  expanded_key_next_4_bytes)

        # the key_schedule is applied to every 32 bytes to expanded_key_next_4_bytes
        if current_size % cipher_key_size == 0:
            expanded_key_next_4_bytes = key_schedule(
                expanded_key_next_4_bytes, round_constant_index)
            round_constant_index += 1
            print("expanded_key_next_4_bytes if current_size resto por cipher_key_size key_schedule",
                  expanded_key_next_4_bytes)

        # an extra SUBSTITUTION_BOX transform is added because of the 256-bit key use
        if current_size % cipher_key_size == 16:
            for i in range(4):
                expanded_key_next_4_bytes[i] = SUBSTITUTION_BOX[expanded_key_next_4_bytes[i]]
                print("expanded_key_next_4_bytes if current_size resto por cipher_key_size == 16",
                      expanded_key_next_4_bytes)

        # the expanded_key_next_4_bytes is XORed with the four-byte block [16,24,32] before the end
        # of the current expanded_key. These four bytes become the next bytes in the expanded_key
        for i in range(4):
            expanded_key.append(
                ((expanded_key[current_size - cipher_key_size]) ^ (expanded_key_next_4_bytes[i])))
            current_size += 1
            print("current_size", current_size)

    print("expanded_key", expanded_key)
    return expanded_key


# make a SUBSTITUTION_BOX transform on each state table's values
def substitution_bytes(state):
    for i in range(len(state)):
        # print "state[i]:", state[i]
        # print "SUBSTITUTION_BOX[state[i]]:", SUBSTITUTION_BOX[state[i]]
        state[i] = SUBSTITUTION_BOX[state[i]]


# make a inverse of SUBSTITUTION_BOX transform on each state table's values
def substitution_bytes_inverse(state):
    for i in range(len(state)):
        state[i] = SUBSTITUTION_BOX_INVERSE[state[i]]


# Galois Field Multiplication Table
def galois_field_multiplation_table(a, b):
    most_significant_bit = 0
    p = 0

    for i in range(8):
        if b & 1 == 1:
            p ^= a
        most_significant_bit = a & 0x80
        a <<= 1
        if most_significant_bit == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256


# mix_column with the galois field multiplication table application
def mix_column(column):
    temp_column = copy(column)

    column[0] = galois_field_multiplation_table(temp_column[0], 2) ^ galois_field_multiplation_table(temp_column[3], 1) ^ \
        galois_field_multiplation_table(
            temp_column[2], 1) ^ galois_field_multiplation_table(temp_column[1], 3)
    column[1] = galois_field_multiplation_table(temp_column[1], 2) ^ galois_field_multiplation_table(temp_column[0], 1) ^ \
        galois_field_multiplation_table(
            temp_column[3], 1) ^ galois_field_multiplation_table(temp_column[2], 3)
    column[2] = galois_field_multiplation_table(temp_column[2], 2) ^ galois_field_multiplation_table(temp_column[1], 1) ^ \
        galois_field_multiplation_table(
            temp_column[0], 1) ^ galois_field_multiplation_table(temp_column[3], 3)
    column[3] = galois_field_multiplation_table(temp_column[3], 2) ^ galois_field_multiplation_table(temp_column[2], 1) ^ \
        galois_field_multiplation_table(
            temp_column[1], 1) ^ galois_field_multiplation_table(temp_column[0], 3)


# mix_column inverse with the galois field multiplication table application
def mix_column_inverse(column):
    temp_column = copy(column)

    column[0] = galois_field_multiplation_table(temp_column[0], 14) ^ galois_field_multiplation_table(temp_column[3], 9) ^ \
        galois_field_multiplation_table(
            temp_column[2], 13) ^ galois_field_multiplation_table(temp_column[1], 11)
    column[1] = galois_field_multiplation_table(temp_column[1], 14) ^ galois_field_multiplation_table(temp_column[0], 9) ^ \
        galois_field_multiplation_table(
            temp_column[3], 13) ^ galois_field_multiplation_table(temp_column[2], 11)
    column[2] = galois_field_multiplation_table(temp_column[2], 14) ^ galois_field_multiplation_table(temp_column[1], 9) ^ \
        galois_field_multiplation_table(
            temp_column[0], 13) ^ galois_field_multiplation_table(temp_column[3], 11)
    column[3] = galois_field_multiplation_table(temp_column[3], 14) ^ galois_field_multiplation_table(temp_column[2], 9) ^ \
        galois_field_multiplation_table(
            temp_column[1], 13) ^ galois_field_multiplation_table(temp_column[0], 11)


# A mix_column wrapper its used to generate a "virtual" column from the state table
# and apply the column mixing
def mix_columns(state):
    for i in range(4):
        column = []

        # create a virtual column by taking the items from each "virtual" row
        for j in range(4):
            column.append(state[j*4+i])

        # apply mix_column on the virtual column
        mix_column(column)

        # attribute the new values to the state table
        for j in range(4):
            state[j*4+i] = column[j]


# A mix_column wrapper its used to generate a "virtual" column from the state table
# and apply the inverse column mixing
def mix_columns_inverse(state):
    for i in range(4):
        column = []

        # create a virtual column by taking the items from each "virtual" row
        for j in range(4):
            column.append(state[j*4+i])

        # apply mix_column on the virtual column
        mix_column_inverse(column)

        # attribute the new values to the state table
        for j in range(4):
            state[j*4+i] = column[j]


# XOR each state-table byte with each round_key byte to generate a new state table byte values
def add_round_key(state, round_key):
    for i in range(len(state)):
        state[i] = state[i] ^ round_key[i]


# creates a sixteen-byte round-key taking sixteen bytes per round from the 240 expanded_key
# to generate each round key
def create_round_key(expanded_key, n):
    return expanded_key[(n*16):(n*16+16)]


# applies each of the round's four transformations
# with the exception of the last round which does not contains the column mixing part
def aes_round(state, round_key):
    substitution_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, round_key)


# applies the inverse of each round's four transformations
# with the exception of the last round which does not contains the column mixing part
def aes_round_inverse(state, round_key):
    add_round_key(state, round_key)
    mix_columns_inverse(state)
    shift_rows_inverse(state)
    substitution_bytes_inverse(state)


# wrapper function for the fourteen aes-rounds because of the 256-bit key use
def aes_rounds(state, expanded_key, num_rounds=14):
    round_key = create_round_key(expanded_key, 0)
    add_round_key(state, round_key)

    for i in range(1, num_rounds):
        round_key = create_round_key(expanded_key, i)
        aes_round(state, round_key)

    # the final round does not include the column mixing transformation
    round_key = create_round_key(expanded_key, num_rounds)
    substitution_bytes(state)
    shift_rows(state)
    add_round_key(state, round_key)


# wrapper function for the fourteen aes-rounds inverse because of the 256-bit key use
def aes_rounds_inverse(state, expanded_key, num_rounds=14):
    # create the round_key for the "last" round since its in the reverse order
    round_key = create_round_key(expanded_key, num_rounds)
    # As it uses XOR, the add_round_key is the same funtion for inverse
    add_round_key(state, round_key)
    shift_rows_inverse(state)
    substitution_bytes_inverse(state)

    for i in range(num_rounds-1, 0, -1):
        round_key = create_round_key(expanded_key, i)
        aes_round_inverse(state, round_key)

    # the final round does not include the column mixing transformation
    round_key = create_round_key(expanded_key, 0)
    add_round_key(state, round_key)


# Use SHA-256 to create a key from a user password
def user_password_to_key(password):
    sha256 = hashlib.sha256()
    password_bytes = password.encode('latin-1')
    sha256.update(password_bytes)

    key = []

    print("password", password)

    digest = sha256.digest()
    print("user_password_to_key sha256 digest", digest)
    print(type(digest))

    if type(digest) is str:
        key = list(map(ord, digest))
    elif type(digest) is bytes:
        key = [ord(chr(byte)) for byte in digest]

    print("key", key)
    return key


# encrypt or decrypt a block (sixteen bytes) of plaintext
def aes_encrypt_or_decrypt_block(plaintext, key):
    block = copy(plaintext)
    expanded_key = expandKey(key)
    aes_rounds(block, expanded_key)
    return block


# return the string-message next block of sixteen characters
# if the string-message next block contains less than sixteen bytes,
# it paddles the block with new n characters.
# With n being the number of characters needed to get sixteen bytes
# when added to the number of bytes left in the string message.
def get_string_next_16_characters(string_to_encrypt, block_number):
    print("block_number[0]", block_number[0])

    # If there are characters left in the string, to encrypt
    if ((block_number[0] * 16) - 16 < len(string_to_encrypt)):
        print("block_number[0] * 16 - 16 < len(string_to_encrypt)",
              block_number[0] * 16 - 16 < len(string_to_encrypt))
        print("block_number[0]", block_number[0])
        print("block_number[0] * 16", block_number[0] * 16)
        print("(block_number[0] * 16) - 16", (block_number[0] * 16) - 16)
        print("len(string_to_encrypt)", len(string_to_encrypt))

        # If there is no character left in the string, to encrypt
        if ((block_number[0] * 16) >= len(string_to_encrypt)):
            print("len(string_to_encrypt) % 16 == 0",
                  len(string_to_encrypt) % 16 == 0)
            return ""

        chunk = string_to_encrypt[block_number[0]*16:block_number[0]*16+16]
        print(
            "chunk = string_to_encrypt[block_number[0]*16:block_number[0]*16+16]", chunk)

        print("chunk type", type(chunk))
        print("string_to_encrypt type", type(string_to_encrypt))

        # Convert characters to ASCII and add them to the list
        block = [ord(char) for char in chunk]
        print("block = [ord(char) for char in chunk]", block)

        # If there are less than sixteen characters left in the string to encrypt,
        # apply padding
        if ((block_number[0] * 16) + 16 > len(string_to_encrypt)):
            numbers_of_characters_left = (
                (block_number[0] * 16) + 16) - len(string_to_encrypt)

            print("numbers_of_characters_left", numbers_of_characters_left)
            print("Entrei no len(string_to_encrypt) % 16 != 0")

            padChar = numbers_of_characters_left
            print(
                "padChar depois do padChar = 16-len(numbers_of_characters_left)", padChar)

            block.extend([padChar for _ in range(numbers_of_characters_left)])
            print(
                "block = [padChar for _ in range(numbers_of_characters_left)", block)

    block_number[0] += 1

    return block


def encrypt_string(string_to_encrypt, password, encrypted_output_string):
    ciphertext = [0] * 16  # ciphertext
    block = [0] * 16  # plaintext

    # Initialization Vector
    initialization_vector = []
    print("initialization_vector vazio", initialization_vector)

    initialization_vector = [185, 177, 50, 124, 65, 90, 169, 171,
                             201, 49, 140, 98, 166, 14, 214, 178]

    # for i in range(16):
    # Depois de converter o codigo para Python 3, tentar substituir esta linha para: initialization_vector.append(secrets.randbelow(256))
    #     initialization_vector.append(randint(0, 255))

    print("initialization_vector depois de ser gerado aleatoriamente com o randInt()",
          initialization_vector)

    # use the user password to generate an AES 256-bit key
    aes_key = user_password_to_key(password)

    # assign the initialization_vector bytes the encrypted_output_string list
    encrypted_output_string = [chr(i) for i in initialization_vector]

    # get the string-message file size in bytes
    file_size = len(string_to_encrypt)

    # read the string-message in blocks of sixteen characters to encrypt
    first_round = True
    print("block antes do primeiro get_string_next_16_characters(string_to_encrypt, block_number)", block)
    block_number = [0]
    block = get_string_next_16_characters(string_to_encrypt, block_number)
    # block = get_next_block_of_16_characters(file_pointer)
    print("block depois do primeiro get_string_next_16_characters(string_to_encrypt, block_number)", block)

    while block != "":
        print("Entrei no while block != \"\" ")
        print("while block != ", block)

        if first_round:
            block_key = aes_encrypt_or_decrypt_block(
                initialization_vector, aes_key)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key)

        # print("ciphertext", ciphertext)
        # print("block", block)
        # print("block", len(block))
        # print("block_key", block_key)

        for i in range(16):
            print("ciphertext", ciphertext)
            print("ciphertext lenght", len(ciphertext))
            print("block", block)
            print("block lenght", len(block))
            print("block_key", block_key)
            print("block_key lenght", len(block_key))
            ciphertext[i] = block[i] ^ block_key[i]

        print("ciphertext depois do xor do block e do block_key", ciphertext)
        # assin the ciphertext to the encrypted_output_string list
        # Convert integers to characters
        ciphertext_char_list = [chr(i) for i in ciphertext]

        # Add each sixteen-byte block ciphertext to the end of the encrypted_output_string list
        encrypted_output_string.extend(ciphertext_char_list)

        print("encrypted_output_string depois de write o ciphertext",
              encrypted_output_string)
        print("type(ciphertext) depois de write o ciphertext", type(ciphertext))
        print("type(encrypted_output_string) depois de write o ciphertext",
              type(encrypted_output_string))

        # get the next sixteen-characters block from the string-message
        block = get_string_next_16_characters(string_to_encrypt, block_number)
        print(
            "entrei no segundo get_string_next_16_characters(string_to_encrypt, block_number)")
        print("block", block)

    print("file_size antes do (if file_size % 16 == 0)", file_size)

    # add an extra padding block if the message ends on a block boundary
    if file_size % 16 == 0:
        # encrypted_output_string.write(16*chr(16))
        encrypted_output_string.extend(16*chr(16))

    print("encrypted_output_string depois (if file_size % 16 == 0)",
          encrypted_output_string)

    encrypted_string = ''.join(encrypted_output_string)
    return encrypted_string


def decrypt_string(string_to_decrypt, password, decrypted_output_string=None):
    plaintext = [0] * 16  # plaintext
    block = [0] * 16  # plaintext

    print("string_to_decrypt dentro e antes decrypt", string_to_decrypt)
    print("string_to_decrypt type", type(string_to_decrypt))

    # use the user password to generate an AES 256-bit key
    aes_key = user_password_to_key(password)

    # recover the initialization vector, the first block in the string-message list
    block_number = [0]
    initialization_vector = get_string_next_16_characters(
        string_to_decrypt, block_number)

    print("initialization_vector depois do initialization_vector = get_string_next_16_characters(string_to_decrypt, block_number)", initialization_vector)
    print(
        "initialization_vector length depois do initialization_vector = get_string_next_16_characters(string_to_decrypt, block_number)", len(initialization_vector))

    string_to_decrypt = string_to_decrypt[16:]
    print("string_to_decrypt = string_to_decrypt[16:]", string_to_decrypt)
    print("string_to_decrypt lenght", len(string_to_decrypt))

    # read the encrypted string-message list in blocks of sixteen characters to decrypt
    first_round = True
    block_number = [0]
    block = get_string_next_16_characters(string_to_decrypt, block_number)
    print("block = get_string_next_16_characters(string_to_decrypt, block_number)", block)

    while block != "":
        if first_round:
            block_key = aes_encrypt_or_decrypt_block(
                initialization_vector, aes_key)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key)

        print("block antes do plaintext[i] = block[i] ^ block_key[i]", block)
        print(
            "block lenght antes do plaintext[i] = block[i] ^ block_key[i]", len(block))
        print(
            "block_key antes do plaintext[i] = block[i] ^ block_key[i]", block_key)
        print(
            "block_key lenght antes do plaintext[i] = block[i] ^ block_key[i]", len(block_key))

        print("plaintext antes do for i in range(16) do decrypt", plaintext)
        print("plaintext lenght antes do for i in range(16) do decrypt", len(plaintext))

        for i in range(16):
            print("i no for i in range(16)", i)
            plaintext[i] = block[i] ^ block_key[i]
            print("plaintext dentro do for i in range(16) do decrypt", plaintext)
            print("plaintext lenght", len(plaintext))

        print("plaintext depois do for i in range(16) do decrypt", plaintext)
        print("plaintext lenght", len(plaintext))

        # throw out the number of bytes represented by the last byte in the block
        # when on the block of text
        if block_number[0] * 16 + 16 > len(string_to_decrypt):
            plaintext = plaintext[0:-(plaintext[-1])]
            print(
                "plaintext dentro do if file_pointer.tell() == file_size do decrypt", plaintext)
            print("plaintext lenght", len(plaintext))

        print("plaintext", plaintext)
        print("plaintext lenght", len(plaintext))

        # Add each sixteen-byte plaintext block to the end of the decrypted_output_string list

        decrypted_output_string.extend([chr(i) for i in plaintext])

        print("decrypted_output_string depois de write o plaintext",
              decrypted_output_string)

        # get the next sixteen-byte block from encrypted string-message list
        block = get_string_next_16_characters(string_to_decrypt, block_number)
        print(
            "block = get_string_next_16_characters(string_to_decrypt, block_number)", block)

    print("plaintext", plaintext)
    print("plaintext lenght", len(plaintext))

    decrypted_string = ''.join(decrypted_output_string)
    return decrypted_string


# return sixteen-byte block from an open file
# if the string-message next block contains less than sixteen bytes,
# it paddles the block with new n characters.
# With n being the number of characters needed to get sixteen bytes
# when added to the number of bytes left in the string message.
def get_next_block_of_16_characters(file_pointer):
    print("file_pointer", file_pointer)
    next_characters = file_pointer.read(16)
    print("next_characters", next_characters)
    print("next_characters lenght", len(next_characters))

    # if reached the end of the file
    if len(next_characters) == 0:
        print("Entrei no if len(next_characters) == 0")
        print("next_characters", next_characters)
        print("next_characters lenght", len(next_characters))
        return ""

    # block list to store sixteen-byte block per time
    block = []
    print("block", block)
    print("block lenght", len(block))

    block = [ord(chr(byte)) for byte in next_characters]
    print("block", block)
    print("block lenght", len(block))

    # if the block is smaller than sixteen-byte size,
    # pad the block with the string value that represents the number of missing bytes
    if len(block) < 16:
        print("Entrei no  if len(block) < 16")
        padChar = 16-len(block)
        print("padChar depois do padChar = 16-len(block)", padChar)
        while len(block) < 16:
            print("Entrei no while len(block) < 16")
            print("block", block)
            print("block lenght", len(block))
            block.append(padChar)

    return block


# wrapper function that allows plaintext encryption
# using Output Feedback (OFB) mode
def encrypt(file_to_encrypt, password, encrypted_output_text_file=None):
    ciphertext = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # ciphertext
    block = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # plaintext

    print("file_to_encrypt", file_to_encrypt)
    print("file_to_encrypt", len(file_to_encrypt))

    # Initialization Vector
    initialization_vector = []
    print("initialization_vector vazio", initialization_vector)

    initialization_vector = [185, 177, 50, 124, 65, 90, 169, 171,
                             201, 49, 140, 98, 166, 14, 214, 178]

    print("initialization_vector depois de ser gerado aleatoriamente com o randInt()",
          initialization_vector)

    password = ""
    # use the user password to generate an AES 256-bit key
    aes_key = user_password_to_key(password)

    # create a handle for the file that will be encrypted
    try:
        file_pointer = open(file_to_encrypt, "rb")
    except:
        print("Cannot open file_to_encrypt -", file_to_encrypt)
        # sys.exit()

    # create a handle for the file that will contain the encrypted message
    if encrypted_output_text_file is not None:
        try:
            opened_text_file_to_encrypt = open(encrypted_output_text_file, "w")
        except:
            print("Cannot open encrypted_output_text_file -",
                  encrypted_output_text_file)
            # sys.exit()
    else:
        file_name = file_to_encrypt+".aes"
        try:
            opened_text_file_to_encrypt = open(file_name, "w")
        except:
            print("Cannot open file_name -", file_name)
            # sys.exit()

    opened_text_file_to_encrypt = open(
        encrypted_output_text_file, "w", encoding="latin-1")

    # Convert the integer bytes to characters using UTF-8 encoding and write to the file
    opened_text_file_to_encrypt.write(
        "".join(chr(byte) for byte in initialization_vector))

    # putting the file pointer at the end of the file
    file_pointer.seek(0, 2)
    # getting the file size in bytes
    file_size = file_pointer.tell()
    # putting the file pointer back at the beginning of the file
    file_pointer.seek(0)

    # read the file in sixteen-byte blocks of input to encrypt
    first_round = True
    print("block antes do primeiro get_next_block_of_16_characters(file_pointer)", block)
    block = get_next_block_of_16_characters(file_pointer)
    print("block depois do primeiro get_next_block_of_16_characters(file_pointer)", block)

    while block != "":
        print("Entrei no while block != \"\" ")
        print("while block != ", block)

        if first_round:
            block_key = aes_encrypt_or_decrypt_block(
                initialization_vector, aes_key)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key)

        # print("ciphertext", ciphertext)
        # print("block", block)
        # print("block", len(block))
        # print("block_key", block_key)

        for i in range(16):
            print("ciphertext", ciphertext)
            print("ciphertext lenght", len(ciphertext))
            print("block", block)
            print("block lenght", len(block))
            print("block_key", block_key)
            print("block_key lenght", len(block_key))
            ciphertext[i] = block[i] ^ block_key[i]

        print("ciphertext depois do xor do block e do block_key", ciphertext)

        # write the sixteen-byte block ciphertext to the opened_text_file_to_encrypt per time
        for c in ciphertext:
            opened_text_file_to_encrypt.write(chr(c))
            print("c dentro do for c in ciphertext", c)
            print("chr(c) dentro do for c in ciphertext", chr(c))
            # print("c lenght dentro do for c in ciphertext", len(c))

            print("chr(c) length dentro do for c in ciphertext", len(chr(c)))
            print("type(c)", type(c))
            print("chr(c) lenght", len(chr(c)))
            print("type(chr(c))", type(chr(c)))
            print("chr(c).isSpace()", chr(c).isspace())

        print("opened_text_file_to_encrypt depois de write o ciphertext", ciphertext)
        print("type(ciphertext) depois de write o ciphertext", type(ciphertext))
        print("type(opened_text_file_to_encrypt) depois de write o ciphertext", type(
            opened_text_file_to_encrypt))

        # get the next sixteen-byte block to be encrypeted from input file
        block = get_next_block_of_16_characters(file_pointer)
        print("entrei no segundo get_next_block_of_16_characters(file_pointer)")
        print("block", block)

    print("file_size antes do (if file_size % 16 == 0)", file_size)

    # add an extra padding block if the message ends on a block boundary
    if file_size % 16 == 0:
        opened_text_file_to_encrypt.write(16*chr(16))

    print("opened_text_file_to_encrypt depois (if file_size % 16 == 0)",
          opened_text_file_to_encrypt)

    # close file pointers
    file_pointer.close()
    opened_text_file_to_encrypt.close()


# wrapper function that allows ciphertext encryption
# using Output Feedback (OFB) mode
def decrypt(file_to_decrypt, password, decrypted_output_text_file=None):
    plaintext = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0]  # plaintext container
    block = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # ciphertext

    password = ""
    # use the user password to generate an AES 256-bit key
    aes_key = user_password_to_key(password)

    # create a handle for the file that will be decrypted
    try:
        file_pointer = open(file_to_decrypt, "rb")
        print(
            "file_pointer depois do file_pointer = open(file_to_decrypt, rb)", file_pointer)
    except:
        print("Cannot open file_to_decrypt -", file_to_decrypt)
        # sys.exit()

    # create handle for file to be decrypted
    # try:
    #     file_pointer = open(file_to_decrypt, "rb")
    #     print(
    #         "file_pointer depois do file_pointer = open(file_to_decrypt, rb)", file_pointer)
    # except:
    #     print("Cannot open file_to_decrypt -", file_to_decrypt)
    #     sys.exit()

    # create a handle for the decrypted_output_text_file
    if decrypted_output_text_file is not None:
        try:
            opened_text_file_to_decrypt = open(
                decrypted_output_text_file, "w", encoding="latin-1")
        except:
            print("Cannot open file_name -", file_name)
            # sys.exit()
    else:
        if file_to_decrypt[-4:] == ".aes":
            file_name = file_to_decrypt[:-4]
            print("Using", file_name, "for decrypted_output_text_file name.")
        else:
            file_name = input("decrypted_output_text_file name: ")
        try:
            opened_text_file_to_decrypt = open(file_name, "w")
        except:
            print("Cannot open file_name -", file_name)
            # sys.exit()

    # recover the initialization vector, the first sixteen-byte block in the encrypted text file
    initialization_vector = get_next_block_of_16_characters(file_pointer)

    # putting the file pointer at the end of the file
    file_pointer.seek(0, 2)
    # getting the file size in bytes
    # to handle the padding at the end of the file
    file_size = file_pointer.tell()
    # putting the file pointer back at the first block of ciphertext
    file_pointer.seek(16)

    print("block antes do block = get_next_block_of_16_characters(file_pointer)", block)
    print(
        "block lenght antes do block = get_next_block_of_16_characters(file_pointer)", len(block))

    # read the sixteen-byte block from the encrypted_text_file to decrypt
    first_round = True
    block = get_next_block_of_16_characters(file_pointer)
    while block != "":
        if first_round:
            block_key = aes_encrypt_or_decrypt_block(
                initialization_vector, aes_key)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key)

        print("block antes do plaintext[i] = block[i] ^ block_key[i]", block)
        print(
            "block lenght antes do plaintext[i] = block[i] ^ block_key[i]", len(block))
        print(
            "block_key antes do plaintext[i] = block[i] ^ block_key[i]", block_key)
        print(
            "block_key lenght antes do plaintext[i] = block[i] ^ block_key[i]", len(block_key))

        print("plaintext antes do for i in range(16) do decrypt", plaintext)
        print("plaintext lenght antes do for i in range(16) do decrypt", len(plaintext))

        for i in range(16):
            plaintext[i] = block[i] ^ block_key[i]
            print("plaintext dentro do for i in range(16) do decrypt", plaintext)
            print("plaintext lenght", len(plaintext))

        # throw out the number of bytes represented by the last byte in the block
        # when in the last block of text
        if file_pointer.tell() == file_size:
            plaintext = plaintext[0:-(plaintext[-1])]
            print(
                "plaintext dentro do if file_pointer.tell() == file_size do decrypt", plaintext)
            print("plaintext lenght", len(plaintext))

        print("plaintext", plaintext)
        print("plaintext lenght", len(plaintext))

        # write sixteen-byte block of plaintext to the opened_text_file_to_decrypt per time
        for c in plaintext:
            opened_text_file_to_decrypt.write(chr(c))
            print("c dentro do for c in plaintext", c)
            print("chr(c) dentro do for c in plaintext", chr(c))

        print("opened_text_file_to_decrypt depois de write o plaintext",
              decrypted_output_text_file)

        # get the next sixteen-byte block from encrypted_text_file
        block = get_next_block_of_16_characters(file_pointer)

    print("plaintext", plaintext)
    print("plaintext lenght", len(plaintext))

    # closing the file pointers
    file_pointer.close()
    opened_text_file_to_decrypt.close()


def print_how_to_use():
    print(
        "-e <input_text_file> | -d <input_text_file>] [(optional) -o <output_text_file>")
    print("Insert your password when asked, after writing the encryption/decryption arguments.\n")
    sys.exit()


def main():

    # containers for the command-line arguments
    input_option = input("Choose input option (1 or 2): ")

    while (input_option != "textfile" and input_option != "string"):
        if (input_option == "1"):
            input_option = "textfile"
        elif (input_option == "2"):
            input_option = "string"
        else:
            print("Invalid option! Select input option: 1 or 2.")

    if (input_option == "textfile"):
        input_parameters = input(
            "Write: option input_text_file option output_text_file: ")

        input_parameters_list = input_parameters.split()

        input_text_file = None
        output_text_file = None

        for a in range(len(input_parameters_list)):
            # print("input_parameters_list", len(input_parameters_list))
            if input_parameters_list[a] == "-e":
                try:
                    input_text_file = input_parameters_list[a+1]
                except:
                    input_text_file = input("File to encrypt: ")
            elif input_parameters_list[a] == "-d":
                try:
                    input_text_file = input_parameters_list[a+1]
                except:
                    input_text_file = input("File to decrypt: ")
            if input_parameters_list[a] == "-o":
                try:
                    output_text_file = input_parameters_list[a+1]
                except:
                    # pass
                    output_text_file = input("Decrypted file name: ")

        # print the help message to the user
        if ("-h" in input_parameters_list) or ("--help" in input_parameters_list):
            print_how_to_use()
        if input_text_file is None:
            print(
                "Error: please write the encryption or decryption arguments.")
            # Depois de converter o codigo para Python 3, vou renomear esta funcao para printHowToUse()
            print_how_to_use()
        # encrypt a file based on the user instructions
        if "-e" in input_parameters_list:
            password = getpass("Password: ")
            print("Encrypting input_text_file:", input_text_file)
            if output_text_file is not None:
                encrypt(input_text_file, password, output_text_file)
            else:
                encrypt(input_text_file, password)
            print("Encryption finished.")
        # decrypt a file based on the user instructions
        elif "-d" in input_parameters_list:
            password = getpass("Password: ")
            print("Decrypting input_text_file:", input_text_file)
            if output_text_file is not None:
                decrypt(input_text_file, password, output_text_file)
            else:
                decrypt(input_text_file, password)
            print("Decryption finished.")

    elif (input_option == "string"):
        string_to_encrypt = input(
            "Write the message to encrypted and decrypted: ")
        # string_to_encrypt
        if string_to_encrypt is None:
            print("Error: please write a message to encrypt and decrypt.")
        else:
            print("string_to_encrypt", string_to_encrypt)
            # encrypt file
            print("Encrypt file.")
            password = getpass("Password: ")
            print("Encrypting message.")
            encrypted_output_string = []
            encrypted_string = encrypt_string(
                string_to_encrypt, password, encrypted_output_string)
            print("Encryption complete.")
            print("encrypted_output_string depois do Encrypt", encrypted_string)
            # decrypt file
            print("Decrypt file.")
            password = getpass("Password: ")
            print("Decrypting message.")
            decrypted_output_string = []
            print("Decryption complete.")
            decrypted_string = decrypt_string(
                encrypted_string, password, decrypted_output_string)
            print("encrypted_output_string depois do decrypt", decrypted_string)


if __name__ == "__main__":
    main()
