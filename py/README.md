Digital Bitbox Python
============

Python code supporting the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.

### Developer interface

Use `send_command.py` and `dbb_utils.py` to communicate with a Digital Bitbox. See the [API](https://digitalbitbox.com/api) for available commands.

Dependencies:

- [Python](http://python.org)
- [Cython](http://cython.org)
- [HIDAPI](https://pypi.python.org/pypi/hidapi)

The code uses the following additional Python libraries: `json`, `base64`, `aes` (slowaes), and `hashlib`.
