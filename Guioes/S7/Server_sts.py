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

conn_cnt = 0
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

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.ca_cert = "MSG_CA.crt"
        with open("MSG_SERVER.key", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=b"1234",
                backend=default_backend()
            )

        with open("MSG_SERVER.crt", "rb") as cert_file:
            certB = cert_file.read()
            self.certB = load_pem_x509_certificate(certB, default_backend())
    
        self.server_public_key = self.private_key.public_key()

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        txt = msg.decode().strip()
        print('%d : %r' % (self.id, txt))
        parts = txt.split(' ')
        cmd = parts[0]
        self.msg_cnt += 1
        
        if cmd == "client_pub_key":
            if isinstance(msg, str):
                msg = msg.encode()
            user_public_key_data = msg.split(b" ")[1:]
            user_public_key_data = b" ".join(user_public_key_data)

            try:
                self.user_public_key = serialization.load_pem_public_key(user_public_key_data, default_backend())

                user_public_key_bytes = self.user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                server_public_key_bytes = self.server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_server_user_pair = mkpair(server_public_key_bytes, user_public_key_bytes)

                signature = self.private_key.sign(
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                if signature:
                    print("Signature created!")
                else:
                    return "Error creating signature!"
                
                p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                g = 2
                parameters_numbers = dh.DHParameterNumbers(p, g)
                parameters = parameters_numbers.parameters(default_backend())

                self.server_private_key_dh = parameters.generate_private_key()
                self.server_public_key_dh = self.server_private_key_dh.public_key()
                
                server_cert_bytes = self.certB.public_bytes(encoding=serialization.Encoding.PEM)
                sig_cert_pair = mkpair(signature, server_cert_bytes)    
                send_pair = mkpair(server_public_key_bytes, sig_cert_pair)
                tudo = mkpair(self.server_public_key_dh.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), send_pair)
                send_pair_b64 = base64.b64encode(tudo)

                send_msg = b"server_pub_key " + send_pair_b64

                return send_msg
            
            except Exception as e:
                print(e)
                return "Error loading user public key!"
        
        elif cmd == "user_cert":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)
            
            user_public_dh_bytes, tudo = unpair(message_data)

            signature, user_cert_bytes = unpair(tudo)

            self.user_cert = x509.load_pem_x509_certificate(user_cert_bytes, default_backend())
            self.user_public_key_dh = serialization.load_pem_public_key(user_public_dh_bytes, default_backend())

            user_pub_key_bytes = self.user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            server_public_key_bytes = self.server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            pub_server_user_pair = mkpair(server_public_key_bytes, user_pub_key_bytes)
            valida.valida_cert(self.user_cert, self.ca_cert)
            try:
                self.user_public_key.verify(
                    signature,
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("User certificate and signature validated!")
                shared_key_dh = self.server_private_key_dh.exchange(self.user_public_key_dh)
                print("Shared key DH created!")
                print(shared_key_dh)
                
                return "User and Client certificates and signatures validated!"
            except Exception as e:
                print(e)
                return "Error validating user certificate and signature!"
        
        else:
            return "Command error!"

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1] == b'\n': break
        response = srvwrk.process(data)
        if isinstance(response, str):
            writer.write(response.encode())
        else:
            writer.write(response)
            await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()

def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Servindo em {}'.format(server.sockets[0].getsockname()))
    print('  (pressione ^C para finalizar)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFinalizado!')

run_server()