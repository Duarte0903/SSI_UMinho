import socket
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_host, self.server_port))

            # Gerar os parâmetros DH
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

            # Gerar a chave privada e a chave pública correspondente
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            # Serializar a chave pública
            serialized_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Enviar a chave pública para o servidor
            s.sendall(serialized_public_key)

            # Receber a chave pública do servidor
            server_public_key_bytes = s.recv(4096)
            server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes,
                backend=default_backend()
            )

            # Derivar a chave compartilhada
            shared_key = private_key.exchange(server_public_key)

            # Derivar uma chave secreta usando HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'encryption key',
                backend=default_backend()
            ).derive(shared_key)

            while True:
                message = input("Digite uma mensagem: ")
                if message.lower() == 'exit':
                    break

                # Enviar mensagem cifrada para o servidor
                s.sendall(derived_key)
                s.sendall(message.encode())

                # Receber resposta do servidor
                data = s.recv(1024)
                print("Resposta do servidor:", data.decode())

if __name__ == "__main__":
    client = Client("localhost", 12345)
    client.run()