###For ctf problems that only provide a server account but no nc service
###Actually, pwntools have this ssh mechanism, but I like to seperate exploit script and accounts
### s = ssh(host=, port=, user=, password=)

import socket
import subprocess

process = ''
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
listener.bind(('0.0.0.0', 10101))
listener.listen(5)

try:
    while True:
        client, addr = listener.accept()
        subprocess.Popen([process], stdin=client, stdout=client, stderr=client)
        client.close()
except KeyboardInterrupt:
    pass
finally:
    listener.close()
