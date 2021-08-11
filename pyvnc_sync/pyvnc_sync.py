import logging
import socket
import struct
import time

from des import DesKey
from PIL import Image

from . import keysym

CHUNK_SIZE = 4096

HANDSHAKE = ""
PIXEL_FORMAT = "BBBBHHHBBBxxx"
SET_PIXEL_FORMAT = "Bxxx16s"
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

logger = logging.getLogger("pyvnc_sync")
logger.setLevel(logging.ERROR)

def _unpack_single(t, data):
    """
    Unpacks and returns the first piece of data from a struct
    """
    try:
        return struct.unpack(t, data)[0]
    except:
        print(data)
        raise


class FrameBuffer(object):
    def __init__(self, width, height, bytes_per_pixel):
        self.width = width
        self.height = height
        self.bytes_per_pixel = bytes_per_pixel
        self.framebuffer = []
        self._init_framebuffer()

    def _init_framebuffer(self):
        blank_pixel = b'\x00' * self.bytes_per_pixel
        blank_row = [blank_pixel] * self.width
        for _ in range(self.height):
            self.framebuffer.append(blank_row.copy())

    def resize(self, width, height):
        self.width = width
        self.height = height
        self._init_framebuffer()

    def set_pixels(self, x_position, y_position, width, height, pixel_bytes):
        """
        Set the pixels to a rectangle at x, y with width, height and
        pixel_bytes.  Will resize the framebuffer as needed if the any pixels
        fall outside the existing width/height.
        """

        logger.debug(f"Setting pixels at x={x_position} y={y_position} width={width} height={height}")
        pixel_matrix = []
        # check to see if pixel_bytes is properly divisible
        if len(pixel_bytes) % (width * self.bytes_per_pixel) != 0:
            raise ValueError(f"Number of pixel bytes received ({len(pixel_bytes)}) is not divisible by width * bytes_per_pixel ({width * self.bytes_per_pixel}).")
        for i in range(height):
            row = []
            for j in range(0, len(pixel_bytes) // height, self.bytes_per_pixel):
                row.append(pixel_bytes[i * width * self.bytes_per_pixel + j : i * width * self.bytes_per_pixel + j + self.bytes_per_pixel])
            pixel_matrix.append(row)

        # check if the framebuffer needs to be resized based on the x, y, width, height
        need_resize = False
        if x_position + width > self.width:
            self.width = x_position + width
            need_resize = True
        if y_position + height > self.height:
            self.height = y_position + height
            need_resize = True
        if need_resize:
            self._init_framebuffer()

        for i, row in enumerate(pixel_matrix):
            if logger.level <= logging.DEBUG: # don't do this extra logic unless debug is on
                row_log = b"".join(row)
                old_row_log = b"".join(self.framebuffer[y_position + i][x_position : x_position + width])
                #logger.debug(f"Old row: \n{old_row_log}\nNew row:\n{row_log}")
            self.framebuffer[y_position + i][x_position : x_position + width] = row
        logger.debug("Done setting pixels")

    def flatten(self):
        """
        Flattens the 2D array of byte strings to a single string of bytes
        """
        return b"".join(map(lambda x: b"".join(x), self.framebuffer))

    def __str__(self):
        s = ""
        for row in self.framebuffer:
            s += str(row) + "\n"
        return s

    

class PixelFormat(object):
    """
    A class for storing the PixelFormat struct
    """

    def __init__(self, bits_per_pixel=32, depth=32, big_endian_flag=0, true_color_flag=1, red_max=65280, green_max=65280, blue_max=65280, red_shift=0, green_shift=8, blue_shift=16):
        # default options here are the preferred pixel_format options and are
        # currently the only supported ones for screenshots to work
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

    def pack(self):
        return struct.pack(PIXEL_FORMAT, self.bits_per_pixel, self.depth, self.big_endian_flag, self.true_color_flag, self.red_max, self.green_max, self.blue_max, self.red_shift, self.green_shift, self.blue_shift)
        

class SyncVNCClient:
    """
    Synchronous VNC client. The goal is to be as stupid simple and barebones as
    possible.
    """

    def __init__(self, hostname, port=5900, password=None, share=False, pixel_format=PixelFormat(), log_level=logging.ERROR):
        logger.setLevel(log_level)
        logging.basicConfig(level=log_level)
        self.s = socket.create_connection((hostname, port))
        self.password = password 
        self.share=share
        self.framebuffer = FrameBuffer(0, 0, 4)
        self.pixel_format = pixel_format
        self.server_pixel_format = None
        self.name = None
        self.mouse_buttons = 0x00
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
        self.server_pixel_format = PixelFormat(*pixel_format)
        self.name = name_string
        self._set_encodings([RAW_ENCODING, DESKTOP_SIZE_ENCODING])
        self._set_pixel_format()

    def _set_pixel_format(self, pixel_format=None):
        if pixel_format is None:
            pixel_format = self.pixel_format
        else:
            self.pixel_format = pixel_format

        self.s.send(struct.pack(SET_PIXEL_FORMAT, 0, pixel_format.pack()))



    def _handle_framebuffer_update(self):
        def _get_rectangle_header():
            x_position = _unpack_single(U16, self.s.recv(2))
            y_position = _unpack_single(U16, self.s.recv(2))
            width = _unpack_single(U16, self.s.recv(2))
            height = _unpack_single(U16, self.s.recv(2))
            encoding_type = _unpack_single(S32, self.s.recv(4))
            logger.debug(f"x={x_position} y={y_position} width={width} height={height} encoding_type={encoding_type}")
            return x_position, y_position, width, height, encoding_type

        def _collect_rectangle(width, height, encoding_type):

            pixel_data = b''
            if encoding_type == RAW_ENCODING:
                num_bytes = width * height * self.pixel_format.bits_per_pixel // 8
                logger.debug(f"Collecting {num_bytes} bytes from socket for rectangle.")
                n = 0
                while n < num_bytes:
                    num_to_grab = min(num_bytes - n, CHUNK_SIZE)
                    buffer = self.s.recv(num_to_grab)
                    pixel_data = pixel_data + buffer
                    n += len(buffer)
                if n > num_bytes:
                    logger.warning("Received wrong number of bytes in rectangle.")
            else:
                raise ValueError(f"Server sent unsupported rectangle encoding: {encoding_type}")
            
            return pixel_data
        
        self.s.recv(1)
        number_of_rectangles = _unpack_single(U16, self.s.recv(2))
        logger.debug(f"{number_of_rectangles} rectangles")
        rectangles = []
        resize = False
        new_width, new_height = 0, 0
        for _ in range(number_of_rectangles):
            logger.debug(f"Processing rectangle {_}")
            pixel_data = []       
            x, y, width, height, encoding_type = _get_rectangle_header()
            if encoding_type == DESKTOP_SIZE_ENCODING:
                resize = True
                new_width, new_height = width, height
            else:
                pixel_data = _collect_rectangle(width, height, encoding_type)
                rectangles.append((x, y, width, height, pixel_data))
        if resize:
            self.framebuffer.resize(new_width, new_height)
        for rectangle in rectangles:
            self.framebuffer.set_pixels(*rectangle)
                

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
        self.s.recv(1)
        length = _unpack_single(U32, self.s.recv(4))
        
        # drop clipboard data nor now
        self.s.recv(length)

    def _handle_server_message(self, message_type):
        message_handler_callbacks = {
            0 : self._handle_framebuffer_update,
            1 : self._handle_set_color_map_entries,
            2 : self._handle_bell,
            3 : self._handle_server_cut_text,
        }
        message_handler_callbacks[message_type]()


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
            message_type = self._check_for_messages()
            if message_type == 0:
                framebuffer_updated = True

    def _check_for_messages(self):
        message_type = self.s.recv(1)[0]
        self._handle_server_message(message_type)
        return message_type

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
        key = self._key_to_keysym(key)
        message = struct.pack(KEY_EVENT, 4, 1, key)
        self.s.send(message) 

    def key_up_event(self, key):
        key = self._key_to_keysym(key)
        message = struct.pack(KEY_EVENT, 4, 0, key)
        self.s.send(message) 
    
    # Press and release a key
    def press_key(self, key, duration=0.01):
        self.key_down_event(key)
        time.sleep(duration)
        self.key_up_event(key)

    def _button_click(self, button, x, y, duration=0.01):
        self.pointer_event(buttons=[button], down=True, x=x, y=y)
        time.sleep(duration)
        self.pointer_event(buttons=[button], down=False, x=x, y=y)

    def left_click(self, x, y, duration=0.01):
        self._button_click(1, x, y, duration)

    def right_click(self, x, y, duration=0.01):
        self._button_click(3, x, y, duration)

    def middle_click(self, x, y, duration=0.01):
        self._button_click(2, x, y, duration)

    def scroll_up(self, x, y, duration=0.01):
        self._button_click(4, x, y, duration)

    def scroll_down(self, x, y, duration=0.01):
        self._button_click(5, x, y, duration)

    def pointer_event(self, buttons=[], down=False, x=0, y=0):
        """
        Edit the current mouse button mask and send it to the server as a pointer event
        Down=False clears the bits in buttons
        Down=True sets the bits in buttons
        IE calling pointer_event(buttons=[1, 2], down=True) will mark the left and middle mouse buttons as down at (0, 0)
        """
        if down:
            # do not affect buttons that are already down
            button_mask = 0x00
        else:
            # do not affect buttons that are already up
            button_mask = 0xFF

        # flip the corresponding bits in the mask
        for button in buttons:
            button_mask ^= 1 << button

        # apply the mask to the mouse_buttons member
        if down:
            self.mouse_buttons |= button_mask
        else:
            self.mouse_buttons &= button_mask

        # send the current mouse_buttons to the server
        event = struct.pack(POINTER_EVENT, 0x05, self.mouse_buttons, x, y)
        self.s.send(event)

    def screenshot(self, filename="screenshot.png", refresh=True, incremental=0, show=False, x=0, y=0, width=1, height=1):
        if refresh:
            self._request_framebuffer_update(x, y, width, height, incremental=incremental)
       
        # Flatten list
        img = Image.frombytes("RGBX", (self.framebuffer.width, self.framebuffer.height), self.framebuffer.flatten())
        rgb_image = img.convert("RGB")
        if show:
            rgb_image.show()
        else:
            rgb_image.save(filename)

#f = FrameBuffer(10, 10, 4)
#f.set_pixels(1, 1, 2, 3, b'\x01\x01\x01\x01' * 6)
client = SyncVNCClient(hostname="localhost", password="navwar", log_level=logging.DEBUG)
time.sleep(5)
client.screenshot(show=True)
print("Mess with the window now")
time.sleep(5)
client.screenshot(show=True)
#client = SyncVNCClient(hostname="localhost", password="test")
#client._request_framebuffer_update(0, 0, 1, 1, incremental=1)
#print("Change resolution now")
#time.sleep(10)
#client._check_for_messages()
#print(f"Current resolution: {client.framebuffer_size}")
#client._request_framebuffer_update(0, 0, 1, 1, incremental=1)
#print(f"Current resolution: {client.framebuffer_size}")
