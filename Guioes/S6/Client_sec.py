import asyncio
import os
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

conn_port = 8441
max_msg_size = 9999
fixed_key_256 = b'\x00' * 32  # 256 bit

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.key = fixed_key_256  # Usando chave fixa de 256 bits
        # Chave AES-GCM

    def process(self, msg=b""):
        self.msg_cnt += 1
        cipher = AESGCM(self.key)
        if msg:
            decrypted_msg = cipher.decrypt(nonce=msg[:12], data=msg[12:], associated_data=b'')
            print('Received (%d): %r' % (self.msg_cnt , decrypted_msg.decode()))
        else:
            print('Received (%d): Connection closed by server' % self.msg_cnt)
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        if len(new_msg) == 0:
            print('Closing connection...')
            return None
        nonce = os.urandom(12)
        encrypted_msg = nonce + cipher.encrypt(nonce=nonce, data=new_msg, associated_data=b'')
        return encrypted_msg if len(encrypted_msg) > 0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    print('Connected to {}'.format(addr))
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()