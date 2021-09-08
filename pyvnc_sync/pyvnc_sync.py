import logging
import socket
import struct
import time

from des import DesKey
from PIL import Image
from threading import Thread, Lock

from . import keysym
from .framebuffer import Framebuffer
from .pixel_format import PixelFormat
from .pixel_format import PIXEL_FORMAT

CHUNK_SIZE = 4096 #65536 #Maybe receiving 64KB at a time will make these framebuffer updates faster?

HANDSHAKE = ""
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

logger = logging.getLogger(__name__)

def _unpack_single(t, data):
    """
    Unpacks and returns the first piece of data from a struct
    """
    try:
        return struct.unpack(t, data)[0]
    except:
        print(data)
        raise

class VNCUnsupportedSecurityTypes(Exception):
    pass

class SyncVNCClient(Thread):
    """
    Synchronous VNC client. The goal is to be as stupid simple and barebones as
    possible.
    """

    def __init__(self, hostname, port=5900, password=None, share=False, pixel_format=PixelFormat(), log_level=logging.INFO, recv_socket_timeout=1):
        super().__init__()
        self._running = False
        logger.setLevel(log_level)
        self.recv_socket_timeout = recv_socket_timeout
        self._socket_lock = Lock()
        self.hostname = hostname
        self.port = port
        self.running = False
        self._send_socket_lock = Lock() # these locks are grabbed before using the socket. both are grabbed while (re)connecting
        self._recv_socket_lock = Lock()
        self._reconnecting_lock = Lock() # do a non blocking grab on this lock while reconnecting if either socket fails
        self.send_socket = None
        self.recv_socket = None
        self.password = password 
        self.share=share
        self.framebuffer = Framebuffer(0, 0, 4)
        self.pixel_format = pixel_format
        self.server_pixel_format = None
        self.vnc_name = ""
        self.mouse_buttons = 0x00
        self._framebuffer_updated = False
        self._please_stop = False
        self._connected_and_initialized = False
        self.first_screenshot = True
        self._reconnecting = False
        self._offset = 0 # sometimes clicks in the same spot don't work?? flip this and add to mouse location to make subsequent clicks always different. super hacky
        self._connect()
    
    def __del__(self):
        if self._running:
            self.stop()
        if self.send_socket is not None:
            self.send_socket.close()
        if self.recv_socket is not None:
            self.recv_socket.close()
    
    def _connect(self, retries=0, retry_sleep=0):
        # try to acquire the reconnect lock. if it's already acquired, another thread is already reconnecting
        with self._reconnecting_lock:
            try:
                self._reconnecting = True
                logger.debug("(Re)connect lock acquired.")
                tries = 0
                # try to (re)connect until successful
                logger.debug(f"(Re)connect waiting for send socket lock.")
                with self._send_socket_lock:
                    logger.debug(f"(Re)connect waiting for recv socket lock.")
                    with self._recv_socket_lock:
                        while (retries == 0 or tries < retries) and not self._connected_and_initialized:
                            logger.info("Connecting to VNC server...")
                            try:
                                # close existing sockets if this is a reconnect
                                if self.send_socket is not None:
                                    self.send_socket.close()
                                if self.recv_socket is not None:
                                    self.recv_socket.close()

                                # create the first socket
                                self.send_socket = socket.create_connection((self.hostname, self.port))

                                # create the second socket using the first sockets file descriptor. this lets python use the same socket in 2 different threads without connecting an entirely separate socket
                                self.recv_socket = socket.fromfd(self.send_socket.fileno(), self.send_socket.family, self.send_socket.type)

                                # set a timeout on the recv_socket so it releases the lock periodically
                                self.recv_socket.settimeout(self.recv_socket_timeout)
                                logger.info("Connected to VNC Server.")
                                logger.info("Initializing VNC connection...")
                                self._protocol_handshake(needs_lock=False)
                                self._security_handshake(needs_lock=False)
                                self._initialization(needs_lock=False)
                                self._connected_and_initialized = True
                                logger.info("VNC initialized.")
                            except KeyboardInterrupt:
                                raise
                            except ConnectionError:
                                if retries != 0 and tries == retries:
                                    logger.error(f"Failed to connect after {retries} tries. Giving up.")
                                    raise
                                logger.warning(f"Connection failed... retrying in {retry_sleep} seconds...")
                                tries += 1
                                if retry_sleep > 0:
                                    time.sleep(retry_sleep)
            finally:
                self._reconnecting = False

    def _protocol_handshake(self, needs_lock=True):
        logger.debug("Conducting protocol handshake")
        self.vnc_server_version = self._full_recv(12, needs_lock=needs_lock)
        if self.vnc_server_version != b'RFB 003.008\x0a':
            raise NotImplementedError(f"Backwards compatibility with older protocol versions is not yet supported: {str(self.vnc_server_version)}")
        self._safe_send(b'RFB 003.008\x0a', needs_lock=needs_lock)
        logger.debug("Protocol handshake successful") 


    def _security_handshake(self, needs_lock=True):
        logger.debug("Conducting security handshake")
        # Get security types 
        number_of_types = _unpack_single(U8, self._full_recv(1, needs_lock=needs_lock))

        # handle server aborting the connection
        if number_of_types == 0:
            self._get_failure_reason()
            
        supported_security_types = self._full_recv(number_of_types, needs_lock=needs_lock)
        supported_security_types = struct.unpack(f'{number_of_types}B', supported_security_types)

        # choose no security by default
        if 1 in supported_security_types:
            self._safe_send(struct.pack(U8, 1), needs_lock=needs_lock)

        # otherwise use VNC security
        elif 2 in supported_security_types:
            if self.password is None:
                raise ValueError("Server requires a password but one was not supplied")

            # select VNC security
            self._safe_send(struct.pack(U8, 2), needs_lock=needs_lock)

            # server sends a randomly generated challenge
            challenge = self._full_recv(16, needs_lock=needs_lock)

            # encrypt the challenge with the password and send it back
            new_password = self._process_password(self.password)
            key = DesKey(new_password)
            response = key.encrypt(challenge)
            self._safe_send(response, needs_lock=needs_lock)

            # Retrieve SecurityResult
            handshake_result = _unpack_single(U32, self._full_recv(4, needs_lock=needs_lock))
            if handshake_result:
                self._get_failure_reason(needs_lock=needs_lock)

        else:
            raise VNCUnsupportedSecurityTypes("VNC Server does not allow any supported security types")
        logger.debug("Security handshake successful")


    def _get_failure_reason(self, needs_lock=True):
        reason_len = _unpack_single(U32, self._full_recv(4, needs_lock=needs_lock))
        reason = self._full_recv(reason_len, needs_lock=needs_lock)
        reason = _unpack_single(STRING.format(reason_len), reason)
        raise ConnectionRefusedError(f"VNC Server refused connection with reason: {reason.decode('ASCII')}")
        

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

    
    def _set_encodings(self, encodings, needs_lock=True):
        message = b''
        message += struct.pack(U8, 2) # message type (set encoding)
        message += struct.pack('x') # padding
        message += struct.pack(U16, len(encodings)) # number of encodings
        for encoding in encodings:
            message += struct.pack(S32, encoding) # raw
        self._safe_send(message, needs_lock=needs_lock)


    def _initialization(self, needs_lock=True):
        logger.debug("Sending initialization messages")
        # ClientInit
        self._safe_send(struct.pack(BOOL, self.share), needs_lock=needs_lock)
        # Start receiving server init
        framebuffer_width = struct.unpack(U16, self._full_recv(2, needs_lock=needs_lock))[0]
        framebuffer_height = struct.unpack(U16, self._full_recv(2, needs_lock=needs_lock))[0]
        pixel_format = struct.unpack(PIXEL_FORMAT, self._full_recv(16, needs_lock=needs_lock))
        name_length = struct.unpack(U32, self._full_recv(4, needs_lock=needs_lock))[0]
        name_string = struct.unpack(STRING.format(name_length), 
                                    self._full_recv(name_length, needs_lock=needs_lock))[0]
        self.server_pixel_format = PixelFormat(*pixel_format)
        self.vnc_name = name_string
        self._set_encodings([RAW_ENCODING, DESKTOP_SIZE_ENCODING], needs_lock=needs_lock)
        self._set_pixel_format(needs_lock=needs_lock)

        # re-init the framebuffer
        self.framebuffer = Framebuffer(framebuffer_width, framebuffer_height, self.pixel_format.bits_per_pixel // 8)
        logger.debug("Initialization messages sent")

    def _set_pixel_format(self, pixel_format=None, needs_lock=True):
        if pixel_format is None:
            pixel_format = self.pixel_format
        else:
            self.pixel_format = pixel_format

        self._safe_send(struct.pack(SET_PIXEL_FORMAT, 0, pixel_format.pack()), needs_lock=needs_lock)



    def _handle_framebuffer_update(self):
        def _get_rectangle_header():
            x_position = _unpack_single(U16, self._full_recv(2))
            y_position = _unpack_single(U16, self._full_recv(2))
            width = _unpack_single(U16, self._full_recv(2))
            height = _unpack_single(U16, self._full_recv(2))
            encoding_type = _unpack_single(S32, self._full_recv(4))
            logger.debug(f"x={x_position} y={y_position} width={width} height={height} encoding_type={encoding_type}")
            return x_position, y_position, width, height, encoding_type

        def _collect_rectangle(width, height, encoding_type):
            pixel_data = b''
            if encoding_type == RAW_ENCODING:
                num_bytes = width * height * self.pixel_format.bits_per_pixel // 8
                logger.debug(f"Collecting {num_bytes} bytes from socket for rectangle.")
                pixel_data = self._full_recv(num_bytes)
                if len(pixel_data) > num_bytes:
                    logger.warning("Received wrong number of bytes in rectangle.")
            else:
                raise ValueError(f"Server sent unsupported rectangle encoding: {encoding_type}")
            
            return pixel_data
        logger.info("Handling framebuffer update") 
        self._full_recv(1)
        number_of_rectangles = _unpack_single(U16, self._full_recv(2))
        logger.debug(f"{number_of_rectangles} rectangles")
        rectangles = []
        resize = False
        new_width, new_height = 0, 0

        # collect the rectangles
        for _ in range(number_of_rectangles):
            logger.debug(f"Processing rectangle {_}")
            pixel_data = []       
            x, y, width, height, encoding_type = _get_rectangle_header()

            # resize the framebuffer
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

        # mark the framebuffer as updated in case a framebuffer update request is waiting
        self._framebuffer_updated = True
                

    def _handle_set_color_map_entries(self):
        logger.info("Handling set color map entries")
        self._full_recv(1)
        _ = _unpack_single(U16, self._full_recv(2))
        number_of_colors = _unpack_single(U16, self._full_recv(2))
        
        # drop color map entries
        self._full_recv(number_of_colors * 6)

    def _handle_bell(self):
        # do nothing
        logger.info("Handling bell")

    def _handle_server_cut_text(self):
        logger.info("Handling server cut text")
        length = _unpack_single(U32, self._full_recv(4))
        self._full_recv(length)

    def _handle_server_message(self, message_type):
        #self.s.settimeout(None)
        message_handler_callbacks = {
            0 : self._handle_framebuffer_update,
            1 : self._handle_set_color_map_entries,
            2 : self._handle_bell,
            3 : self._handle_server_cut_text,
        }
        #print(f"handling message {message_type}")
        message_handler_callbacks[message_type]()
        #self.s.settimeout(self._socket_timeout)

    def _request_framebuffer_update(self, x, y, width, height, incremental=1):
        message = struct.pack(U8, 3)
        message += struct.pack(U8, incremental)
        message += struct.pack(U16, x)
        message += struct.pack(U16, y)
        message += struct.pack(U16, width)
        message += struct.pack(U16, height)
        self._safe_send(message)
        self._framebuffer_updated = False # set framebuffer updated to false
        while not self._framebuffer_updated: # block until the framebuffer is updated by the response handler thread
            time.sleep(0.1)
        self._framebuffer_updated = True

    def _safe_send(self, *args, needs_lock=True, **kwargs):
        try:
            if self.send_socket is not None:
                if needs_lock:
                    logger.debug("Waiting for send socket lock.")
                    with self._send_socket_lock:
                        logger.debug("Send socket lock acquired.")
                        self.send_socket.send(*args, **kwargs)
                else:
                    self.send_socket.send(*args, **kwargs)
        except ConnectionError as e:
            logger.warning(f"Send thread caught ConnectionError {e} - reconnecting")
            logger.debug("Closing send socket")
            self._connected_and_initialized = False
            if self.send_socket is not None:
                self.send_socket.close()
            logger.debug("Closing recv socket")
            if self.recv_socket is not None:
                self.recv_socket.close()
            logger.debug("Reconnecting")
            self._connect()

            logger.debug("Retry the send")
            # try the send again
            self._safe_send(*args, needs_lock=needs_lock, **kwargs)
            logger.warning(f"Send successfully recovered.")
        logger.debug(f"Send {args[0]}")

    def _safe_recv(self, *args, retry_on_timeout=True, needs_lock=True, **kwargs):
        do_while = True # emulate a do while loop
        success = False # set to true after successful recv
        d = b''
        while do_while or (retry_on_timeout and not success and not self._please_stop):
            do_while = False
            try:
                if self.recv_socket is not None:
                    if needs_lock: 
                        logger.debug("Acquiring recv socket lock...")
                        if self._recv_socket_lock.acquire(blocking=False):
                            try:
                                logger.debug("Recv socket lock acquired.")
                                d = self.recv_socket.recv(*args, **kwargs)
                            finally:
                                self._recv_socket_lock.release()
                        else:
                            logger.debug("Recv lock already held")
                    else:
                        d = self.recv_socket.recv(*args, **kwargs)
                    success = True
            except socket.timeout:
                logger.debug("Recv timed out.")

        logger.debug(f"Received data: {d}")
        return d

    def _full_recv(self, bufsize, *args, needs_lock=True, **kwargs):
        buf = b''
        n = 0
        while n < bufsize and not self._please_stop:
            buf += self._safe_recv(min(bufsize - n, CHUNK_SIZE), needs_lock=needs_lock, *args, **kwargs)
            n = len(buf)
        return buf

    def _timeout_send(self, *args, **kwargs):
        try:
            self._safe_send(*args, **kwargs)
        except socket.timeout:
            pass

    def _timeout_recv(self, *args, **kwargs):
        try:
            return self._full_recv(*args, **kwargs)
        except socket.timeout:
            pass
        return None

    def _check_for_messages(self):
        message = self._safe_recv(1, retry_on_timeout=False)
        if message:
            message_type = message
            self._handle_server_message(message_type[0])
        else:
            message_type = None
        return message_type

    def refresh_resolution(self):
        """
        Requests an incremental framebuffer update with only 1 pixel. Hopefully
        the server actually only sends back 1 pixel, but there's no guarantee.
        """
        self._request_framebuffer_update(0, 0, 1, 1, incremental=1)

    def refresh_framebuffer(self):
        """
        Requests a full framebuffer update. This takes a hot second.
        """
        self._request_framebuffer_update(0, 0, 1, 1, incremental=0)

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
        self._safe_send(message) 

    def key_up_event(self, key):
        key = self._key_to_keysym(key)
        message = struct.pack(KEY_EVENT, 4, 0, key)
        self._safe_send(message) 
    
    # Press and release a key
    def press_key(self, key, duration=0.1):
        logger.info(f"Pressing {key}")
        self.key_down_event(key)
        time.sleep(duration)
        self.key_up_event(key)

    def _button_click(self, button, x, y, duration=0.1):
        logger.info(f"Button {button} click at {x}, {y} for {duration} seconds.")
        self.pointer_event(x=x, y=y)
        time.sleep(duration)
        #print("pointer event 1")
        self.pointer_event(buttons=[button], down=True, x=x, y=y)
        #print("sleeping")
        time.sleep(duration)
        #print("pointer event 2")
        self.pointer_event(buttons=[button], down=False, x=x, y=y)

    def left_click(self, x, y, duration=0.1):
        self._button_click(1, x, y, duration)

    def right_click(self, x, y, duration=0.1):
        self._button_click(3, x, y, duration)

    def middle_click(self, x, y, duration=0.1):
        self._button_click(2, x, y, duration)

    def scroll_up(self, x, y, duration=0.1):
        self._button_click(4, x, y, duration)

    def scroll_down(self, x, y, duration=0.1):
        self._button_click(5, x, y, duration)

    def pointer_event(self, buttons=[], down=False, x=0, y=0):
        """
        Edit the current mouse button mask and send it to the server as a pointer event
        Down=False clears the bits in buttons
        Down=True sets the bits in buttons
        IE calling pointer_event(buttons=[1, 2], down=True) will mark the left and middle mouse buttons as down at (0, 0)
        """
        if x == self.framebuffer.width - 1:
            x -= self._offset
        else:
            x += self._offset
        if y == self.framebuffer.height - 1:
            y -= self._offset
        else:
            y += self._offset

        self._offset ^= 1 # flip offset flag

        if down:
            # do not affect buttons that are already down
            button_mask = 0x00
        else:
            # do not affect buttons that are already up
            button_mask = 0xFF

        # flip the corresponding bits in the mask
        for button in buttons:
            button_mask ^= 1 << (button - 1)
        # apply the mask to the mouse_buttons member
        if down:
            self.mouse_buttons |= button_mask
        else:
            self.mouse_buttons &= button_mask

        logger.debug(self.mouse_buttons)
        # send the current mouse_buttons to the server
        event = struct.pack(POINTER_EVENT, 0x05, self.mouse_buttons, x, y)
        self._safe_send(event)

    def screenshot(self, filename="screenshot.png", refresh=True, incremental=0, show=False, x=0, y=0, width=1, height=1):
        
        # Always need to call with incremental = 0 to actually get a screenshot.
        # Seems to get a blank screen otherwise.
        self._request_framebuffer_update(x, y, width, height, incremental=0)

        # If this is not the 1st screenshot, then use incremental=2.
        if not self.first_screenshot:
            self._request_framebuffer_update(x, y, 1447, 737, incremental=2)
        

        # Flatten list
        img = Image.frombytes("RGBX", (self.framebuffer.width, self.framebuffer.height), self.framebuffer.flatten())
        rgb_image = img.convert("RGB")
        if show:
            rgb_image.show()
        else:
            rgb_image.save(filename)
        self.first_screenshot = False
        
        
        

    def cut_buffer(self, buffer):
        length = len(buffer)
        message = struct.pack(U8, 6)
        message += struct.pack('x') 
        message += struct.pack('x') 
        message += struct.pack('x') 
        message += struct.pack(U32, length)
        for b in buffer:
            message += struct.pack(U8, ord(b))
        self._safe_send(message)

    def stop(self):
        self._please_stop = True
        if self._running:
            self.join()
            self.running = False

    def run(self):
        self._running = True
        while not self._please_stop:
            try:
                self._check_for_messages()
            except ConnectionError as e:
                logger.warning(f"Receive thread caught ConnectionError {e} - waiting for reconnection")

                # wait until the main thread tries to start reconnecting
                while not self._reconnecting:
                    time.sleep(0.5)

                # wait until the reconnection is finished
                with self._reconnecting_lock:
                    self._reconnecting = False
                logger.warning("Receive thread detected successful reconnection.")
