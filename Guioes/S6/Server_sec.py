import asyncio
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

conn_cnt = 0
conn_port = 8441
max_msg_size = 9999
fixed_key_256 = b'\x00' * 32  # 256 bit

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.key = fixed_key_256  # Usando chave fixa de 256 bits

    def process(self, msg):
        self.msg_cnt += 1
        if len(msg) < 12:
            print('Closing connection...')
            return None
        cipher = AESGCM(self.key)
        decrypted_msg = cipher.decrypt(nonce=msg[:12], data=msg[12:], associated_data=b'')
        txt = decrypted_msg.decode()
        print('%d : %r' % (self.id, txt))
        new_msg = txt.upper().encode()
        nonce = os.urandom(12)
        encrypted_msg = nonce + cipher.encrypt(nonce=nonce, data=new_msg, associated_data=b'')
        return encrypted_msg if len(encrypted_msg) > 0 else None

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    print("Connection from {}".format(addr))
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while data: 
        data = srvwrk.process(data)
        if data:
            writer.write(data)
            await writer.drain()
            data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()

def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
