import socket
import sys
from Crypto.Cipher import AES

class ServerWorker:
    def __init__(self, conn):
        self.conn = conn

    def process(self):
        # Chave de criptografia
        key = b'minha_chave_secreta'  # Chave fixa para simplificação

        # Inicialização do cipher
        cipher = AES.new(key, AES.MODE_GCM)

        # Receber chave do cliente
        client_key = self.conn.recv(1024)

        while True:
            # Receber mensagem cifrada e tag
            ciphertext = self.conn.recv(1024)
            tag = self.conn.recv(16)

            # Decifrar a mensagem
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            print("Mensagem recebida:", plaintext.decode())

            # Responder ao cliente
            self.conn.sendall(b"Recebido")

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
