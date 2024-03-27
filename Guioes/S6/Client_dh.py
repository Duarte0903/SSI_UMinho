# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

conn_port = 8443
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.shared_key = None

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1

        if self.msg_cnt == 1:
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            server_private_key = parameters.generate_private_key()

            peer_private_key = parameters.generate_private_key()
            shared_key = server_private_key.exchange(peer_private_key.public_key())

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data'
            ).derive(shared_key)

            return peer_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()

        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    print('Connected to {}'.format(addr))
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg :
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