import asyncio
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import socket

conn_port = 8443
max_msg_size = 9999
dh_prime = 23  # Primo utilizado no acordo de chaves Diffie-Hellman

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        try:
            with open("MSG_CLI1.key", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=b'1234',
                    backend=default_backend()
                )
        except ValueError as e:
            print("Error loading client private key:", e)
            self.private_key = None
            raise RuntimeError("Exiting due to key loading errors.")

        try:
            with open("MSG_CLI1.crt", "rb") as cert_file:
                self.certA = cert_file.read()
                cert = load_pem_x509_certificate(self.certA, default_backend())
                self.client_public_key = cert.public_key()
        except ValueError as e:
            print("Error loading server public key:", e)
            self.server_public_key = None
            raise RuntimeError("Exiting due to key loading errors.")

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
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        if self.msg_cnt == 1:  # Primeira mensagem enviada pelo cliente
            # Envio gx (calculado aleatoriamente pelo cliente)
            gx = b"gx_generated_by_client"  # Isso precisa ser corrigido
            self.gx = gx
            print("Sending gx to Server.")
            return gx

        elif self.msg_cnt == 2:  # Segunda mensagem enviada pelo cliente
            # Recebendo gy, SigB(gy, gx), CertB do servidor
            gy_sig_certB = msg
            gy, sigB_gy_gx_certB = Client.unpair(gy_sig_certB)
            sigB_gy_gx, certB = Client.unpair(sigB_gy_gx_certB)
            
            # Carregar a chave pública do servidor a partir do certificado
            cert = load_pem_x509_certificate(certB, default_backend())
            self.server_public_key = cert.public_key()

            # Verificação da assinatura
            try:
                self.server_public_key.verify(
                    sigB_gy_gx,
                    self.mkpair(gy, self.gx),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature from Server verified successfully.")
            except InvalidSignature:
                print("Invalid Signature from Server. Aborting.")
                # Fechar o socket, se necessário
                if hasattr(self, 'sckt') and isinstance(self.sckt, socket.socket):
                    self.sckt.close()
                # Abortar a execução do cliente
                return None
            # Gerar a chave compartilhada K = g(x*y)
            shared_key = pow(int(gy), int(self.gx), dh_prime)
            shared_key_bytes = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big')

            # Envio SigA(gx, gy), CertA
            sigA_gx_gy = self.private_key.sign(
                self.mkpair(self.gx, gy),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            sigA_gx_gy_certA = Client.mkpair(sigA_gx_gy, self.certA)
            print("Sending SigA(gx, gy), CertA to Server.")
            return sigA_gx_gy_certA, shared_key_bytes

        elif self.msg_cnt == 3:  # Terceira mensagem enviada pelo cliente
            # Processa mensagem recebida após estabelecer a chave compartilhada
            if msg:
                # Se houver uma mensagem do servidor, decodificamos e imprimimos
                print("Received message from Server:", msg.decode())
            
            # Solicita ao usuário uma nova mensagem para enviar ao servidor
            print("Input message to send (empty to finish):")
            new_msg = input().encode()
            
            if len(new_msg) == 0:
                print("Closing connection...")
                return None  # Encerra a conexão
            else:
                # Encripta a mensagem e a envia para o servidor
                encrypted_msg = self.server_public_key.encrypt(
                    new_msg,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return encrypted_msg if len(encrypted_msg) > 0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process(None)  # Passa None como a primeira mensagem
    while msg:
        writer.write(msg)
        await writer.drain()
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