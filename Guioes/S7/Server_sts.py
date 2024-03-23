# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999
key_i = 10
key = key_i.to_bytes(16, 'big')

# Carregar a chave privada do servidor
with open("MSG_SERVER.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b'1234',
    )

# Carregar o certificado do servidor
with open("MSG_SERVER.crt", "rb") as cert_file:
    server_cert = x509.load_pem_x509_certificate(cert_file.read())

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, 'little')
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], 'little')
    x = xy[2:len_x+2]
    y = xy[len_x+2:]
    return x, y

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.aead = AESGCM(key)

    def process(self, msg):
        txt = msg.decode()
        print('%d : %r' % (self.id, txt))
        decrypted_text = self.aead.decrypt(nonce=b'unique_nonce', data=txt, associated_data=None)
        print('%d : %r' % (self.id, decrypted_text))
        new_msg = txt.upper().encode()
        encrypted_msg = self.aead.encrypt(nonce=b'unique_nonce', data=new_msg, associated_data=None)
        return encrypted_msg if len(encrypted_msg) > 0 else None
    
    def sign_message(self, msg):
        signature = private_key.sign(
            msg.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    data = await reader.read(max_msg_size)

    while True:
        if not data:
            continue
        if data[:1] == b'\n':
            break

        data = srvwrk.process(data)

        if not data:
            break

        # Assinar a mensagem e enviar a chave pública, assinatura e certificado
        signature = srvwrk.sign_message(data.decode())
        public_key = private_key.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        message_to_send = mkpair(serialized_public_key, signature.encode())

        # Adicionar certificado ao início da mensagem
        cert_bytes = server_cert.public_bytes(serialization.Encoding.PEM)
        message_to_send = cert_bytes + message_to_send

        writer.write(message_to_send)
        await writer.drain()

        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)

    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()