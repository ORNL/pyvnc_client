import socket
import struct
import sys
import time

from des import DesKey
from keysym import BS, ENTER

HANDSHAKE = ""
PIXEL_FORMAT = "BBBBHHHBBBxxx"

U8 = 'B'
U16 = '>H'
U32 = '>L'
S8 = 'b'
S16 = '>h'
S32 = '>l'
STRING = "{}s"

class VClient:

    def __init__(self):
        self.s = socket.create_connection(("localhost", 5900))
        self.password = b'password'
    
    def __del__(self):
        self.s.close()

    #Performs the protocol handshake
    def protocol_handshake(self):
        self.vnc_server_version = self.s.recv(12)
        self.s.send(b'RFB 003.008\n')

    #Performs the security handshake
    def security_handshake(self):
        # Get security types 
        types = self.s.recv(4096)
        # use VNC security
        self.s.send(b'\x02')
        challenge = self.s.recv(4096)
        new_password = self.solve_challenge(challenge)
        key = DesKey(new_password)
        response = key.encrypt(challenge)
        # Send back the encrypted challenge
        self.s.send(response)
        # Retrieve SecurityResult
        self.s.recv(4096)

    # Solves the server's challenge
    def solve_challenge(self, challenge):
        # encrypt challenge with password
        new_password = bytearray()
        for b in self.password:
            _b = 0x00
            for i in range(8):
                mask = 0b1 << i
                shift_count = (7 - (i * 2))
                if shift_count < 0:
                    _b |= (b & mask) >> abs(shift_count)
                else:
                    _b |= (b & mask) << shift_count
            new_password.append(_b)
        new_password = bytes(new_password)
        return new_password


    # Sends ClientInit and receives ServerInit
    def initialization(self):
        # ClientInit (don't share)
        self.s.send(b'\x00')
        # Start receiving server init
        framebuffer_width = struct.unpack(U16, self.s.recv(2))[0]
        framebuffer_height = struct.unpack(U16, self.s.recv(2))[0]
        pixel_format = struct.unpack(PIXEL_FORMAT, self.s.recv(16))
        name_length = struct.unpack(U32, self.s.recv(4))[0]
        name_string = struct.unpack(STRING.format(name_length), 
                                    self.s.recv(name_length))[0]
        print(framebuffer_width, framebuffer_height, pixel_format, name_string)
    
  

    # Press a key. This type it once
    def press_key_event(self, key):
        message = struct.unpack(STRING.format(8),
                                b'\x04\x01\x00\x00\x00\x00' + key)[0]
        self.s.send(message)
        
        
    # Release a key that has already been pressed. Typing a key
    # without releasing it causes repeated key strokes to not
    # work well
    def release_key_event(self, key):
        message = struct.unpack(STRING.format(8),
                                b'\x04\x00\x00\x00\x00\x00' + key)[0]
        self.s.send(message)

    
    # Press and release a key
    def type_key(self, key):
        self.press_key_event(key)
        self.release_key_event(key)

    # Types an entire ASCII string
    def write_string(self, string):
        for char in string:
            bytes_ = struct.pack(U16, ord(char))
            self.type_key(bytes_)
    
    def pointer_event(self, left=False, middle=False, right=False, up=False, down=False, x=b'\x00\x00', y=b'\x00\x00'):
        button_mask = 0x00
        if left:
            button_mask |= 0x01
        
        if middle:
            button_mask |= 0x02

        if right:
            button_mask |= 0x04

        if up:
            button_mask |= 0x08

        if down:
            button_mask |= 0x10
        
        bm_bytes = struct.pack(U8, button_mask)
        event = struct.unpack(STRING.format(6),
                                b'\x05' + bm_bytes + x + y)[0]
        self.s.send(event)
        event = struct.unpack(STRING.format(6),
                                b'\x05\x00' + x + y)[0]
        self.s.send(event)


client = VClient()
client.protocol_handshake()
client.security_handshake()
client.initialization()
time.sleep(5)
client.pointer_event(left=True, x=b'\x04\xff', y=b'\x00\x00')
