import struct

PIXEL_FORMAT = "BBBBHHHBBBxxx"
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
