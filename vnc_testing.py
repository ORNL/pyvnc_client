import socket
import struct
import time

from des import DesKey

HANDSHAKE = ""
PIXEL_FORMAT = "BBBBHHHBBBxxx"

U8 = 'B'
U16 = '>H'
U32 = '>L'
S8 = 'b'
S16 = '>h'
S32 = '>l'
BOOL = '?'
STRING = "{}s"

def _unpack_single(t, data):
    """
    Unpacks and returns the first piece of data from a struct
    """
    try:
        return struct.unpack(t, data)[0]
    except:
        print(data)
        raise

class SyncVNCClient:
    """
    Synchronous VNC client. Goal is to be as stupid simple and barebones as
    possible.
    """

    def __init__(self, hostname, port=5900, password=None, share=False):
        self.s = socket.create_connection((hostname, port))
        self.password = password 
        self.share=share
        self._connect()
    
    def __del__(self):
        self.s.close()

    def _connect(self):
        self._protocol_handshake()
        self._security_handshake()
        self._initialization()

    def _protocol_handshake(self):
        self.vnc_server_version = self.s.recv(4096)
        if self.vnc_server_version == b'RFB 003.008\\n':
            raise NotImplementedError(f"Backwards compatibility with older protocal versions is not yet supported: {str(self.vnc_server_version)}")
        self.s.send(b'RFB 003.008\n')

    def _security_handshake(self):
        # Get security types 
        types = self.s.recv(4096)
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
            challenge = self.s.recv(4096)

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
        failure_packet = self.s.recv(4096)
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
        self.server_pixel_formats = pixel_format
        self.name = name_string

    

    def _handle_framebuffer_update(self, message):
        number_of_rectangles = _unpack_single(U16, message[2:])
        pass

    def _handle_set_color_map_entries(self, message):
        pass

    def _handle_bell(self, message):
        pass

    def _handle_server_cut_text(self, massage):
        pass

    def _handle_server_message(self, message):
        message_handler_callbacks = {
            0 : self._handle_framebuffer_update,
            1 : self._handle_set_color_map_entries,
            2 : self._handle_bell,
            3 : self._handle_server_cut_text,
        }
        message_handler_callbacks[message[0]]
  
    def _request_framebuffer_update(self, location):
        pass

    def _get_update_resolution(self, location):
        pass

    def press_key_event(self, key):
        message = struct.unpack(STRING.format(8),
                                b'\x04\x01\x00\x00\x00\x00' + key)[0]
        self.s.send(message) 

    def release_key_event(self, key):
        #message = b'\x04\x00\x00\x00\x00\x00' + key
        message = struct.unpack(STRING.format(8),
                                b'\x04\x00\x00\x00\x00\x00' + key)[0]
        self.s.send(message)

client = SyncVNCClient(hostname="localhost", password="wrong password")
time.sleep(5)
client.press_key_event(b'\x00\x61')
client.press_key_event(b'\x00\x62')
time.sleep(1)
client.release_key_event(b'\x00\x61')
client.release_key_event(b'\x00\x62')
