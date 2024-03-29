import asyncio
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999
dh_prime = 23  # Primo utilizado no acordo de chaves Diffie-Hellman

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.gx = None
        with open("MSG_SERVER.key", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password= b'1234',
                backend=default_backend()
            )
            self.server_public_key = self.private_key.public_key()

        with open("MSG_SERVER.crt", "rb") as cert_file:
            self.certB = cert_file.read()
            cert = load_pem_x509_certificate(self.certB, default_backend())
            
    @staticmethod
    def mkpair(x, y):
        """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
        len_x = len(x)
        len_x_bytes = len_x.to_bytes(2, "little")
        return len_x_bytes + x + y

    @staticmethod
    def unpair(xy):
        """extrai componentes de um par codificado com 'mkpair'"""
        len_x = int.from_bytes(xy[:2], "little")
        x = xy[2 : len_x + 2]
        y = xy[len_x + 2 :]
        return x, y

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        if self.msg_cnt == 1:  # Primeira mensagem recebida pelo servidor
            # Recebendo gx do cliente
            gx = msg
            print("Received gx from Client.")
            self.gx = gx
            # Gerando gy (calculando aleatoriamente)
            gy = self.server_public_key.encode()
            # Assinando gy, gx e enviando para o cliente
            data_to_sign = self.mkpair(gy, self.gx)
            signature = self.private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signed_data = self.mkpair(signature, data_to_sign)
            print("Sending gy, SigB(gy, gx), CertB to Client.")
            return self.mkpair(gy, signed_data)

        elif self.msg_cnt == 2:  # Segunda mensagem recebida pelo servidor
            # Recebendo SigA(gx, gy), CertA do cliente
            sigA_gx_gy_certA = msg
            sigA_gx_gy, certA = self.unpair(sigA_gx_gy_certA)
            # Verificação da assinatura
            try:
                self.client_public_key.verify(
                    sigA_gx_gy,
                    self.mkpair(self.gx, self.gy),  # Corrigido: Usar self.gy ao invés de gy
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature from Client verified successfully.")
            except InvalidSignature:
                print("Invalid Signature from Client. Aborting.")
                return None
            # A partir daqui, a comunicação é criptografada, portanto não há necessidade de processar mensagens.
            return None

        elif self.msg_cnt == 3:  # Terceira mensagem recebida pelo servidor
            # Processa mensagem recebida após estabelecer a chave compartilhada
            if msg:
                # Se houver uma mensagem do cliente, decodificamos e imprimimos
                print("Received message from Client:", msg.decode())
            
            # Solicita ao servidor uma nova mensagem para enviar ao cliente
            print("Input message to send (empty to finish):")
            new_msg = input().encode()
            
            if len(new_msg) == 0:
                print("Closing connection...")
                return None  # Encerra a conexão
            else:
                # Encripta a mensagem e a envia para o cliente
                encrypted_msg = self.client_public_key.encrypt(
                    new_msg,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return encrypted_msg if len(encrypted_msg) > 0 else None

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1] == b'\n': break
        data = srvwrk.process(data)
        if not data: break
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