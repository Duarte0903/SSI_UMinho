import socket
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class ServerWorker:
    def __init__(self, conn):
        self.conn = conn

    def process(self):
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

        # Enviar a chave pública para o cliente
        self.conn.sendall(serialized_public_key)

        # Receber a chave pública do cliente
        client_public_key_bytes = self.conn.recv(4096)
        client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes,
            backend=default_backend()
        )

        # Derivar a chave compartilhada
        shared_key = private_key.exchange(client_public_key)

        # Derivar uma chave secreta usando HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption key',
            backend=default_backend()
        ).derive(shared_key)

        while True:
            # Receber mensagem cifrada do cliente
            client_key = self.conn.recv(32)
            ciphertext = self.conn.recv(1024)

            # Decifrar a mensagem
            decrypted_message = self.decrypt_message(ciphertext, derived_key)

            print("Mensagem recebida:", decrypted_message.decode())

            # Responder ao cliente
            self.conn.sendall(b"Recebido")

    def decrypt_message(self, ciphertext, key):
        # Decifrar a mensagem usando a chave derivada
        return ciphertext  # Aqui deve implementar a decifração usando AES ou outra cifra simétrica com a chave derivada

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 12345))
        s.listen()

        while True:
            conn, addr = s.accept()
            print("Conexão estabelecida com", addr)
            worker = ServerWorker(conn)
            worker.process()

if __name__ == "__main__":
    main()