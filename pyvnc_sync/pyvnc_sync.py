import socket
import struct
import time


from des import DesKey
from PIL import Image

from keysym import *

CHUNK_SIZE = 4096

HANDSHAKE = ""
PIXEL_FORMAT = "BBBBHHHBBBxxx"
POINTER_EVENT = "!BBHH"
KEY_EVENT = "!BBxxL"

U8 = 'B'
U16 = '!H'
U32 = '!L'
S8 = 'b'
S16 = '!h'
S32 = '!l'
BOOL = '?'
STRING = "{}s"

RAW_ENCODING = 0
DESKTOP_SIZE_ENCODING = -223

def _unpack_single(t, data):
    """
    Unpacks and returns the first piece of data from a struct
    """
    try:
        return struct.unpack(t, data)[0]
    except:
        print(data)
        raise

class PixelFormat(object):
    def __init__(self, bits_per_pixel, depth, big_endian_flag, true_color_flag, red_max, green_max, blue_max, red_shift, green_shift, blue_shift):
        self.bits_per_pixel = bits_per_pixel
        self.depth = depth
        self.big_endian_flag = big_endian_flag
        self.true_color_flag = true_color_flag
        self.red_max = red_max
        self.green_max = green_max
        self.blue_max = blue_max
        self.red_shift = red_shift
        self.green_shift = green_shift
        self.blue_shift = blue_shift

class SyncVNCClient:
    """
    Synchronous VNC client. The goal is to be as stupid simple and barebones as
    possible.
    """

    def __init__(self, hostname, port=5900, password=None, share=False):
        self.s = socket.create_connection((hostname, port))
        self.password = password 
        self.share=share
        self.framebuffer_size = None
        self.pixel_format = None
        self.name = None
        self._connect()
    
    def __del__(self):
        self.s.close()

    
    def _connect(self):
        self._protocol_handshake()
        self._security_handshake()
        self._initialization()


    def _protocol_handshake(self):
        self.vnc_server_version = self.s.recv(CHUNK_SIZE)
        if self.vnc_server_version == b'RFB 003.008\\n':
            raise NotImplementedError(f"Backwards compatibility with older protocal versions is not yet supported: {str(self.vnc_server_version)}")
        self.s.send(b'RFB 003.008\n')


    def _security_handshake(self):
        # Get security types 
        types = self.s.recv(CHUNK_SIZE)
        number_of_types = struct.unpack(U8, types[:1])[0]

        # handle server aborting the connection
        if number_of_types == 0:
            self._get_failure_reason()
            
        supported_security_types = struct.unpack(f'{number_of_types}B', types[1:])

        # choose no security by default
        if 1 in supported_security_types:
            self.s.send(struct.pack(U8, 1))

        # otherwise use VNC security
        elif 2 in supported_security_types:
            if self.password is None:
                raise ValueError("Server requires a password but one was not supplied")

            # select VNC security
            self.s.send(struct.pack(U8, 2))

            # server sends a randomly generated challenge
            challenge = self.s.recv(CHUNK_SIZE)

            # encrypt the challenge with the password and send it back
            new_password = self._process_password(self.password)
            key = DesKey(new_password)
            response = key.encrypt(challenge)
            self.s.send(response)

            # Retrieve SecurityResult
            handshake_result = _unpack_single(U32, self.s.recv(4))
            if handshake_result:
                self._get_failure_reason()

        else:
            raise ConnectionError("VNC Server does not allow any supported security types")


    def _get_failure_reason(self):
        failure_packet = self.s.recv(CHUNK_SIZE)
        reason_len = _unpack_single(U32, failure_packet[:4])
        reason = _unpack_single(STRING.format(reason_len), failure_packet[4:])
        raise ConnectionError(f"VNC Server refused connection with reason: {reason.decode('ASCII')}")
        

    def _process_password(self, password):
        # encrypt challenge with password
        new_password = bytearray()

        # pad password with null bits if it's too short, truncate if too long
        password = password.encode('ASCII') + b'\x00' * 8
        password = password[:8]

        # for some silly reason you have to reverse the bit order of each of
        # the individual bytes of the password
        for b in password:
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

    
    def _set_encodings(self, encodings):
        message = b''
        message += struct.pack(U8, 2) # message type (set encoding)
        message += struct.pack('x') # padding
        message += struct.pack(U16, len(encodings)) # number of encodings
        for encoding in encodings:
            message += struct.pack(S32, encoding) # raw
        # message += struct.pack(S32, DESKTOP_SIZE_ENCODING) #DesktopSize pseudo-encoding
        self.s.send(message)


    def _initialization(self):
        # ClientInit
        self.s.send(struct.pack(BOOL, self.share))
        # Start receiving server init
        framebuffer_width = struct.unpack(U16, self.s.recv(2))[0]
        framebuffer_height = struct.unpack(U16, self.s.recv(2))[0]
        pixel_format = struct.unpack(PIXEL_FORMAT, self.s.recv(16))
        name_length = struct.unpack(U32, self.s.recv(4))[0]
        name_string = struct.unpack(STRING.format(name_length), 
                                    self.s.recv(name_length))[0]
        self.framebuffer_size = (framebuffer_width, framebuffer_height)
        self.pixel_format = PixelFormat(*pixel_format)
        self.name = name_string
        self._set_encodings([RAW_ENCODING, DESKTOP_SIZE_ENCODING])

    def _handle_framebuffer_update(self):
        def _get_rectangle_header():
            x_position = _unpack_single(U16, self.s.recv(2))
            y_position = _unpack_single(U16, self.s.recv(2))
            width = _unpack_single(U16, self.s.recv(2))
            height = _unpack_single(U16, self.s.recv(2))
            encoding_type = _unpack_single(S32, self.s.recv(4))
            return x_position, y_position, width, height, encoding_type

        def _process_rectangle(width, height, encoding_type):
            if encoding_type == DESKTOP_SIZE_ENCODING:
                print(f"Processing desktop size change rectangle: ({width}, {height})")
                self.framebuffer_size = (width, height)
            elif encoding_type == RAW_ENCODING:
                # just drop pixel data for now
                print("RAW rectangle")
                num_bytes = width * height * self.pixel_format.bits_per_pixel // 8
                print(f"Grabbing {num_bytes} bytes")
                n = 0
                
                all_bytes = []

                while n < num_bytes:
                    num_to_grab = min(num_bytes, CHUNK_SIZE)
                    buffer = self.s.recv(num_to_grab)
                    all_bytes.append(buffer)
                    n += len(buffer)
            else:
                raise ValueError(f"Server sent unsupported rectangle encoding: {encoding_type}")
            
            return all_bytes
        
        self.s.recv(1)
        number_of_rectangles = _unpack_single(U16, self.s.recv(2))
        print(f"Number of rectangles: {number_of_rectangles}")
        data = []       
        width, height = 0, 0
        for i in range(number_of_rectangles):
            print(f"Processing rectangle: {i}")
            _, _, width, height, encoding_type = _get_rectangle_header()
            data.append(_process_rectangle(width, height, encoding_type))
        return data, width, height

    def _handle_set_color_map_entries(self):
        self.s.recv(1)
        _ = _unpack_single(U16, self.s.recv(2))
        number_of_colors = _unpack_single(U16, self.s.recv(2))
        
        # drop color map entries
        self.s.recv(number_of_colors * 6)

    def _handle_bell(self):
        # do nothing
        pass

    def _handle_server_cut_text(self):
        print(self.s.recv(1))
        length = _unpack_single(U32, self.s.recv(4))
        print(length)
        # drop clipboard data for now
        print(self.s.recv(length))

    def _handle_server_message(self, message_type):
        message_handler_callbacks = {
            0 : self._handle_framebuffer_update,
            1 : self._handle_set_color_map_entries,
            2 : self._handle_bell,
            3 : self._handle_server_cut_text,
        }

        data, width, height = None, 0, 0
        if message_type == 0:
            data, width, height = message_handler_callbacks[message_type]()
        else:
            message_handler_callbacks[message_type]()


        return data, width, height


    def _request_framebuffer_update(self, x, y, width, height, incremental=1):
        message = struct.pack(U8, 3)
        message += struct.pack(U8, incremental)
        message += struct.pack(U16, x)
        message += struct.pack(U16, y)
        message += struct.pack(U16, width)
        message += struct.pack(U16, height)
        self.s.send(message)
        framebuffer_updated = False
        while not framebuffer_updated:
            message_type, data, width, height = self._check_for_messages()
            if message_type == 0:
                framebuffer_updated = True
            return data, width, height
        return None, None, None

    def _check_for_messages(self):
        message_type = self.s.recv(1)[0]
        print(message_type)
        data, width, height = self._handle_server_message(message_type)
        return message_type, data, width, height

    def _refresh_resolution(self):
        self._request_framebuffer_update(0, 0, 1, 1, incremental=1)


    def _key_to_keysym(self, key):
        # single character basic ascii text
        if len(key) == 1 and ord(key) > 0x1f and ord(key) < 0x7f:
            return ord(key)

        # key in special_keys dict
        elif key in keysym.special_keys:
            return keysym.special_keys[key]

        # assume key is raw binary already
        else:
            return key

    def key_down_event(self, key):
        print(f"Pressing key {key}.")
        key = self._key_to_keysym(key)
        message = struct.pack(KEY_EVENT, 4, 1, key)
        self.s.send(message) 

    def key_up_event(self, key):
        print(f"Releasing key {key}.")
        key = self._key_to_keysym(key)
        message = struct.pack(KEY_EVENT, 4, 0, key)
        self.s.send(message) 
    
    # Press and release a key
    def press_key(self, key, duration=0.01):
        self.key_down_event(key)
        time.sleep(duration)
        self.key_up_event(key)

    def _pointer_event(self, left=False, middle=False, right=False, up=False, down=False, x=0, y=0):
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
        
        
        #Click
        event = struct.pack(POINTER_EVENT, 0x05, button_mask, x, y)
        self.s.send(event)
        
        #Release
        event = struct.pack(POINTER_EVENT, 0x05, 0x00, x, y)
        self.s.send(event)
            
    def left_click(self, x=0, y=0):
        self._pointer_event(left=True, x=x, y=y)

    def middle_click(self, x=0, y=0):
        self._pointer_event(middle=True, x=x, y=y)

    def right_click(self, x=0, y=0):
        self._pointer_event(right=True, x=x, y=y)

    def up_scroll(self, distance=1):
        for i in range(distance): 
            self._pointer_event(up=True)

    def down_scroll(self, distance=1):
        for i in range(distance): 
            self._pointer_event(down=True)

    def screenshot(self, filename="screenshot.png"):
        data, width, height = client._request_framebuffer_update(0, 0, 1, 1, incremental=0)
        
        
        # Flatten list. https://stackabuse.com/python-how-to-flatten-list-of-lists
        # allbytes should now be a list of bytes
        if (data, width, height) != (None, None, None):
            allbytes = [d for sub_data in data[0] for d in sub_data]   
            
            for i in range(0, len(allbytes), 4):
                pixel = allbytes[i:i+4]
                tmp = pixel[0]
                pixel[0] = pixel[2]
                pixel[2] = tmp
                allbytes[i:i+4] = pixel
                
            
            image_data = bytes(allbytes)

            img = Image.frombytes("RGBX", (width, height), image_data)
            img.show()
            img = img.convert("RGB")
            img.save(filename)


    def cut_buffer(self, buffer):
        length = len(buffer)
        message = struct.pack(U8, 6)
        message += struct.pack('x') 
        message += struct.pack('x') 
        message += struct.pack('x') 
        message += struct.pack(U32, length)
        for b in buffer:
            message += struct.pack(U8, ord(b))
        self.s.send(message)



client = SyncVNCClient(hostname="localhost", password="password")
#client._handle_server_cut_text()
#time.sleep(5)
#client._check_for_messages()
