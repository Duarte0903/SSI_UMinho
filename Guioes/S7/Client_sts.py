import asyncio
import base64
import valida_cert as valida
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh

conn_port = 8443
max_msg_size = 9999

def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.ca_cert = "MSG_CA.crt"
        try:
            with open("MSG_CLI1.key", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=b"1234",
                    backend=default_backend()
                )
        except ValueError as e:
            print("Error loading client private key:", e)
            self.private_key = None
            raise RuntimeError("Exiting due to key loading errors.")

        try:
            with open("MSG_CLI1.crt", "rb") as cert_file:
                certA = cert_file.read()
                self.certA = load_pem_x509_certificate(certA, default_backend())
        except ValueError as e:
            print("Error loading server public key:", e)
            self.server_public_key = None
            raise RuntimeError("Exiting due to key loading errors.")
    
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        cmd_parts = msg.decode().split(' ')

        cmd = cmd_parts[0]
        args = cmd_parts[1:]

        if cmd == "pub_key":
            self.client_public_key = self.private_key.public_key()
            print("Client public key loaded!")
            self.pseudonym = self.certA.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            send_msg = b"client_pub_key " + self.client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            return send_msg
        
        elif cmd == "server_pub_key":
            if isinstance(msg, str):
                msg = msg.encode()

            server_key_data_b64 = msg.split(b' ')[1]
            full_pair = base64.b64decode(server_key_data_b64)
            
            server_public_dh_bytes, tudo = unpair(full_pair)

            server_public_key_bytes, sig_cert_pair = unpair(tudo)

            signature, server_cert_bytes = unpair(sig_cert_pair)

            self.server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())

            self.server_public_key = serialization.load_pem_public_key(server_public_key_bytes, default_backend())
            self.server_public_key_dh = serialization.load_pem_public_key(server_public_dh_bytes, default_backend())

            user_pub_key_bytes = self.client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_server_user_pair = mkpair(server_public_key_bytes, user_pub_key_bytes)
            valida.valida_cert(self.server_cert, self.ca_cert)
            try:

                self.server_public_key.verify(
                    signature,
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                user_sig = self.private_key.sign(
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                if user_sig:
                    print("Signature created!")
                else:
                    return "Error creating signature!"
                
                p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                g = 2
                parameters_numbers = dh.DHParameterNumbers(p, g)
                parameters = parameters_numbers.parameters(default_backend())

                self.user_private_key_dh = parameters.generate_private_key()
                self.user_public_key_dh = self.user_private_key_dh.public_key()

                shared_key_dh = self.user_private_key_dh.exchange(self.server_public_key_dh)
                print("Shared key DH created!")
                print(shared_key_dh)
                
                user_sig_pair = mkpair(user_sig, self.certA.public_bytes(encoding=serialization.Encoding.PEM))
                tudo = mkpair(self.user_public_key_dh.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), user_sig_pair)
                user_sig_pair_b64 = base64.b64encode(tudo)
                send_msg = b"user_cert " + user_sig_pair_b64

                return send_msg
            except Exception as e:
                print("Error:", e)
                return "Error creating or verifying signature!"

        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        if isinstance(msg, str):
            msg = msg.encode()

        if msg == b'pub_key':
            msg = client.process(msg)

        writer.write(msg)
        await writer.drain()

        if msg == b'User data not loaded!':
            print(msg.decode())
            msg = client.process()

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