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
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        cipher = AESGCM(self.key)
        if msg:
            decrypted_msg = cipher.decrypt(nonce=msg[:12], data=msg[12:], associated_data=b'')
            print('Received (%d): %r' % (self.msg_cnt , decrypted_msg.decode()))
        else:
            print('Received (%d): Connection closed by server' % self.msg_cnt)
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        return new_msg if len(new_msg) > 0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    while True:
        msg = client.process()
        if not msg:
            break
        cipher = AESGCM(client.key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, msg, associated_data=b'')
        writer.write(nonce + ciphertext)
        await writer.drain()
        msg = await reader.read(max_msg_size)
        if msg:
            if len(msg) < 8 or len(msg) > 128:
                print("Erro: O tamanho do nonce recebido está fora do intervalo esperado.")
                break
            nonce_received = msg[:12]
            ciphertext_received = msg[12:]
            try:
                decrypted_msg = cipher.decrypt(nonce=nonce_received, data=ciphertext_received, associated_data=b'')
                print('Received (%d): %r' % (client.msg_cnt, decrypted_msg.decode()))
            except cryptography.exceptions.InvalidTag:
                print("Erro: Autenticação da mensagem falhou. A mensagem pode ter sido adulterada.")
        else:
            break
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(tcp_echo_client())

run_client()
