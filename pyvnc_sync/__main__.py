import time
from .pyvnc_sync import SyncVNCClient

if __name__ == "__main__":
    c = SyncVNCClient("localhost", password="password")
    c.start()
    time.sleep(10)
    print("Left clicking start")
    c.left_click(5, c.framebuffer.height - 5)
    time.sleep(1)
    print("double clicking 10 10")
    c.left_click(10, 10)
    c.left_click(10, 10)
    c.stop()
