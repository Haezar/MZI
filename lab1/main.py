import sys

# The base class shared by des, double des and triple self.
class BaseDes(object):
    def __init__(self, pad=None):
        if pad:
            pad = self.must_be_bytes(pad)
        self.block_size = 8
        
        # Set the passed in variables
        self._padding = pad

    def get_key(self):
        return self.__key

    def set_key(self, key):
        key = self.must_be_bytes(key)
        self.__key = key

    def get_padding(self):
        return self._padding

    def set_padding(self, pad):
        if pad is not None:
            pad = self.must_be_bytes(pad)
        self._padding = pad

    def pad_data(self, data, pad):
        # Pad data
        if len(data) % self.block_size == 0:
            # No padding required.
            return data
        if not pad:
            # Get the default padding.
            pad = self.get_padding()
        if not pad:
            raise ValueError("Data must be a multiple of " + str(self.block_size) + " bytes in length. Set the pad character.")
        data += (self.block_size - (len(data) % self.block_size)) * pad

        return data

    def unpad_data(self, data, pad):
        # Unpad data
        if not data:
            return data

        if not pad:
            # Get the default padding.
            pad = self.get_padding()
        if pad:
            data = data[:-self.block_size] + \
                   data[-self.block_size:].rstrip(pad)

        return data

    def must_be_bytes(self, data):
        # Only accept byte strings or ascii unicode values, otherwise
        # there is no way to correctly decode the data into bytes.
        if isinstance(data, str):
            # Only accept ascii unicode values.
            try:
                return data.encode('ascii')
            except UnicodeEncodeError:
                pass
            raise ValueError("This program can only work with encoded strings, not Unicode.")
        return data

##################################################
#                     DES                        #
##################################################
class Des(BaseDes):
    
    # Permutation and translation tables for DES
    PC_1 = [56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
    ]

    # number left rotations of PC_1
    left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # permuted choice key (table 2)
    PC_2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    # initial permutation IP
    IP = [57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    # Expansion table for turning 32 bit blocks into 48 bits
    E = [
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

    # The (in)famous S-boxes
    S_box = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]


    # 32-bit permutation function P used on the output of the S-boxes
    P = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23,13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

    # final permutation IP^-1
    IP_reversed = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]

    # Type of crypting being done
    ENCRYPT = 0
    DECRYPT = 1

    # Initialisation
    def __init__(self, key, pad=None):
        # Sanity checking of arguments.
        if len(key) != 8:
            raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
        BaseDes.__init__(self, pad)
        self.key_size = 8

        self.L = []
        self.R = []
        self.Kn = [ [0] * 48 ] * 16    # 16 48-bit keys (K1 - K16)
        self.final = []

        self.set_key(key)

    def set_key(self, key):
        BaseDes.set_key(self, key)
        self.create_sub_keys()

    def string_to_bits(self, data):
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            i = 7
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1

        return result

    def bits_to_string(self, data):
        result = []
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result.append(c)
                c = 0
            pos += 1

        return bytes(result)
            

    #permute this block with the specified table
    def permute(self, table, block):
        return list(map(lambda x: block[x], table))
    
    # Transform the secret key, so that it is ready for data processing
    # Create the 16 subkeys, K[1] - K[16]
    def create_sub_keys(self):
        key = self.permute(self.PC_1, self.string_to_bits(self.get_key()))
        i = 0
        # Split into Left and Right sections
        self.L = key[:28]
        self.R = key[28:56]
        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < self.left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]

                self.R.append(self.R[0])
                del self.R[0]

                j += 1

            # Create one of the 16 subkeys through PC_2 permutation
            self.Kn[i] = self.permute(self.PC_2, self.L + self.R)

            i += 1

    # Main part of the encryption algorithm, the number cruncher :)
    def des_crypt(self, block, crypt_type):
        block = self.permute(self.IP, block)
        self.L = block[:32]
        self.R = block[32:]

        # Encryption starts from Kn[1] through to Kn[16]
        if crypt_type == self.ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        # Decryption starts from Kn[16] down to Kn[1]
        else:
            iteration = 15
            iteration_adjustment = -1

        i = 0
        while i < 16:
            # Make a copy of R[i-1], this will later become L[i]
            tempR = self.R[:]

            # permute R[i - 1] to start creating R[i]
            self.R = self.permute(self.E, self.R)

            # Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
            self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
            B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
        
            # permute B[1] to B[8] using the S-Boxes
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                # Work out the offsets
                m = (B[j][0] << 1) + B[j][5]
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

                # Find the permutation value
                v = self.S_box[j][(m << 4) + n]

                # Turn value into bits, add it to result: Bn
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1

                pos += 4
                j += 1

            # permute the concatination of B[1] to B[8] (Bn)
            self.R = self.permute(self.P, Bn)

            # Xor with L[i - 1]
            self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
            self.L = tempR

            i += 1
            iteration += iteration_adjustment
        
        # Final permutation of R[16]L[16]
        self.final = self.permute(self.IP_reversed, self.R + self.L)
        return self.final


    # Data to be encrypted/decrypted
    def crypt(self, data, crypt_type):

        # Error check the data
        if not data:
            return ''
        if len(data) % self.block_size != 0:
            if crypt_type == self.DECRYPT: # Decryption must work on 8 byte blocks
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self.get_padding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * self.get_padding()
                
        # Split the data into blocks, crypting each one seperately
        i = 0
        dict = {}
        result = []
        
        while i < len(data):                
            block = self.string_to_bits(data[i:i+8])
            processed_block = self.des_crypt(block, crypt_type)
            result.append(self.bits_to_string(processed_block))
            i += 8

        # Return the full crypted string
        return bytes.fromhex('').join(result)
            

    def encrypt(self, data, pad=None):
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        data = self.pad_data(data, pad)
        return self.crypt(data, self.ENCRYPT)

    def decrypt(self, data, pad=None):
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        data = self.crypt(data, self.DECRYPT)
        return self.unpad_data(data, pad)


#################################################
#                 Double DES                    #
#################################################
class DoubleDes(BaseDes):
    def __init__(self, key, pad=None):
        BaseDes.__init__(self, pad)
        self.key_size = 16
        self.set_key(key)

    def set_key(self, key):
        if len(key) != self.key_size:
            raise ValueError("Invalid double DES key size. Key must be 16 bytes long")
                
        self.__key1 = Des(key[:8], self._padding)
        self.__key2 = Des(key[8:], self._padding)
            
        BaseDes.set_key(self, key)

    # Override setter methods to work on all 2 keys.
    def set_padding(self, pad):
        BaseDes.set_padding(self, pad)
        for key in (self.__key1, self.__key2):
            key.set_padding(pad)

    def encrypt(self, data, pad=None):
        ENCRYPT = Des.ENCRYPT
        DECRYPT = Des.DECRYPT
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        # Pad the data accordingly.
        data = self.pad_data(data, pad)
        data = self.__key1.crypt(data, ENCRYPT)
        return self.__key2.crypt(data, DECRYPT)
            

    def decrypt(self, data, pad=None):
        ENCRYPT = Des.ENCRYPT
        DECRYPT = Des.DECRYPT
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        data = self.__key2.crypt(data, ENCRYPT)
        data = self.__key1.crypt(data, DECRYPT)
        return self.unpad_data(data, pad)


#################################################
#                 Triple DES                    #
#################################################
class TripleDes(BaseDes):
    def __init__(self, key, pad=None):
        BaseDes.__init__(self, pad)
        self.key_size = 24
        self.set_key(key)

    def set_key(self, key):
        if len(key) != self.key_size:
            raise ValueError("Invalid triple DES key size. Key must be 24 bytes long")
                
        self.__key1 = Des(key[:8], self._padding)
        self.__key2 = Des(key[8:16], self._padding)
        self.__key3 = Des(key[16:], self._padding)
            
        BaseDes.set_key(self, key)

    # Override setter methods to work on all 3 keys.
    def set_padding(self, pad):
        BaseDes.set_padding(self, pad)
        for key in (self.__key1, self.__key2, self.__key3):
            key.set_padding(pad)

    def encrypt(self, data, pad=None):
        ENCRYPT = Des.ENCRYPT
        DECRYPT = Des.DECRYPT
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        # Pad the data accordingly.
        data = self.pad_data(data, pad)
        data = self.__key1.crypt(data, ENCRYPT)
        data = self.__key2.crypt(data, DECRYPT)
        return self.__key3.crypt(data, ENCRYPT)
            

    def decrypt(self, data, pad=None):
        ENCRYPT = Des.ENCRYPT
        DECRYPT = Des.DECRYPT
        data = self.must_be_bytes(data)
        if pad is not None:
            pad = self.must_be_bytes(pad)
        data = self.__key3.crypt(data, DECRYPT)
        data = self.__key2.crypt(data, ENCRYPT)
        data = self.__key1.crypt(data, DECRYPT)
        return self.unpad_data(data, pad)

file = open("MZI1_text.txt", "r")
data = file.read().encode()
print(data)
print()
k = Des(b"DESCRYPT", pad=b"\1")
d = k.encrypt(data)
print("Encrypted: %r" % d)
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d) == data
print()

k = DoubleDes(b"DESCRYPTREALREAL", pad=b"\1")
d = k.encrypt(data)
print("Encrypted: %r" % d)
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d) == data
print()
k = TripleDes(b"DESCRYPTREALREALHOOLHOOL", pad=b"\1")
d = k.encrypt(data)
print("Encrypted: %r" % d)
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d) == data

