import logging

logger = logging.getLogger(__name__)
class Framebuffer(object):
    """
    A very slow (but (hopefully?) reliable) class for tracking a framebuffer
    """

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
            #if logger.level <= logging.DEBUG: # don't do this extra logic unless debug is on
                #row_log = b"".join(row)
                #old_row_log = b"".join(self.framebuffer[y_position + i][x_position : x_position + width])
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
