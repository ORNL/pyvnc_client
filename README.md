## pyvnc_client

This module is a Python3 VNC client written from scratch that _doesn't_ use the `rfb.py` twisted framework Python class that every other open source Python VNC project seems to use. It's very bare bones at the moment, but as long as you don't care about fast framebuffer updates or security, it's pretty reliable at sending keystrokes and mouse events.

Currently the module is called pyvnc\_sync as we were originally trying to make it fully synchronous. Those familiar with the RFB protocol will know that this is not possible. We are currently in the process of refactoring to the new name pyvnc\_client.

The public API will soon undergo some pretty large additions as we break a lot of the private API methods out of the main class into other classes. For now, the public API is should be simple enough to figure out from source code.

## Example

```python
from pyvnc_sync.pyvnc_sync import SyncVNCClient

c = SyncVNCClient("<hostname>", port=<port>, password="<vnc password>") # this will open the sockets and initialize the connection to the VNC server
c.start() # this will start the thread which listens for asynchronous updates from the server
c.left_click(10, 20) # left click at position x=10 y=20
c.stop() # manually stop and join the listener thread, though this isn't strictly necessary as the __del__ method will also stop the thread and close all open socket objects.
```
