import asyncio
import datetime
import os
import valida_cert as valida
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
parameters_numbers = dh.DHParameterNumbers(p, g)
parameters = parameters_numbers.parameters(default_backend())

help_str = "Usage:\n-user <FNAME>\tSpecify user data file (default: userdata.p12)\n" \
            "send <UID> <SUBJECT>\tSend a message\n" \
            "askqueue\tRequest unread messages\n" \
            "getmsg <NUM>\tRetrieve a specific message\n" \
            "help\tPrint this help message\n"

message_queues = {}            # filas de mensagens dos utilizadores UID -> lista de mensagens (mensagem -> <NUM> <SENDER> <TIMESTAMP> <SUBJECT> <MESSAGE> <STATUS>)
user_derived_keys_dict = {}    # dicionário de chaves derivadas dos utilizadores (UID -> chave pública)
user_dh_public_keys_dict = {}  # dicionário de chaves públicas DH dos utilizadores (UID -> chave pública DH)
user_rsa_public_keys_dict = {} # dicionário de chaves públicas RSA dos utilizadores (UID -> chave pública RSA)

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key, self.server_cert, self.ca_cert = get_userdata("projCA/MSG_SERVER.p12")

        self.server_public_key = self.private_key.public_key()

        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        txt = msg.decode().strip()
        print('%d : %r' % (self.id, txt))
        parts = txt.split(' ')
        command = parts[0]

        if command == "send":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            uid_sender_pair, sub_message_pair = unpair(message_data)

            uid, sender = unpair(uid_sender_pair)

            subject, encrypted_message_pair = unpair(sub_message_pair)

            encrypted_message, signature = unpair(encrypted_message_pair)

            public_key = user_rsa_public_keys_dict[sender]

            verified = False
            try:
                public_key.verify(
                    signature, 
                    encrypted_message, 
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()), 
                        salt_length=padding.PSS.MAX_LENGTH
                    ), 
                    hashes.SHA256()
                )
                verified = True

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error verifying message signature!"
            
            if verified:
                print("Signature verified!")

                try:
                    cipher = Cipher(algorithms.AES(user_derived_keys_dict[sender]), modes.CTR(b'\0' * 16), backend=default_backend())
                    decryptor = cipher.decryptor()
                    message = decryptor.update(encrypted_message) + decryptor.finalize()

                except Exception as e:
                    print(e)
                    return "MSG RELAY SERVICE: error decrypting message!"

                stored_message = (sender, datetime.datetime.now(), subject, message, signature, uid, False)

                if uid in message_queues.keys():
                    message_queues[uid].append(stored_message)
                else:
                    message_queues[uid] = [stored_message]

                return "MSG RELAY SERVICE: message sent and stored!"
               
        elif command == "user_pub_key":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            try:
                user_pseudonym, user_dh_public_key_bytes = unpair(message_data)

                user_dh_public_key = serialization.load_pem_public_key(user_dh_public_key_bytes, default_backend())

                user_dh_public_key_bytes = user_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                server_dh_public_key_bytes = self.dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_server_user_pair = mkpair(server_dh_public_key_bytes, user_dh_public_key_bytes)

                signature = self.private_key.sign(
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                print("User signature verified!")
                
                # Guardar a chave pública DH do utilizador
                user_dh_public_keys_dict[user_pseudonym] = user_dh_public_key

                server_cert_bytes = self.server_cert.public_bytes(encoding=serialization.Encoding.PEM)

                sig_cert_pair = mkpair(signature, server_cert_bytes)    
                
                send_pair = mkpair(server_dh_public_key_bytes, sig_cert_pair)
                send_pair_b64 = base64.b64encode(send_pair)

                print("Server sent public DH key!")

                send_msg = b"server_key " + send_pair_b64

                return send_msg
            
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error loading user public key!"
            
        elif command == "user_cert":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            signature, user_cert_bytes = unpair(message_data)

            user_cert = x509.load_pem_x509_certificate(user_cert_bytes, default_backend())

            try:
                # Validação do certificado do utilizador
                valida.valida_cert(user_cert, self.ca_cert)
                print("User certificate validated!")

                user_dh_public_key = user_dh_public_keys_dict[user_cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value.encode()]
                user_dh_pub_key_bytes = user_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                server_dh_public_key_bytes = self.dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_user_server_pair = mkpair(user_dh_pub_key_bytes, server_dh_public_key_bytes)

                user_rsa_public_key = user_cert.public_key()

                # Validação da assinatura do utilizador
                user_rsa_public_key.verify(
                    signature,
                    pub_user_server_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                shared_key = self.dh_private_key.exchange(user_dh_public_key)
                print("Shared key derived!")

                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)
                print("Derived key generated!")
                
                # Guardar chaves do utilizador
                user_pseudonym = user_cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value.encode()
                user_rsa_public_keys_dict[user_pseudonym] = user_rsa_public_key
                user_derived_keys_dict[user_pseudonym] = derived_key

                return "MSG RELAY SERVICE: user certificate and signature validated!"

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error validating user certificate and signature!"
            
        elif command == "askqueue":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)
            
            user, signature = unpair(message_data)

            public_key = user_derived_keys_dict[user]

            valid = False
            # verificar se a chave pública de utilizador valida a assinatura
            try:
                user_rsa_public_keys_dict[user].verify(
                    signature,
                    user,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                valid = True

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error validating command signature!"
                
            if valid:
                print("User signature verified!")

                if user in message_queues.keys():
                    unread_messages = []

                    for i, message in enumerate(message_queues[user]):
                        if not message[-1]:
                            return_message = f"{i}:{message[0].decode()}:{str(message[1])}:{message[2].decode()}"
                            unread_messages.append(return_message)

                    unread_messages = str(unread_messages).encode()

                    cipher = Cipher(algorithms.AES(user_derived_keys_dict[user]), modes.CTR(b'\0' * 16), default_backend())
                    encryptor = cipher.encryptor()
                    encrypted_message = encryptor.update(unread_messages) + encryptor.finalize()

                    return_signature = self.private_key.sign(
                        encrypted_message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    signature_unread_msgs_pair = mkpair(return_signature, encrypted_message)

                    signature_unread_msgs_pair_b64 = base64.b64encode(signature_unread_msgs_pair)

                    return b'user_queue ' + signature_unread_msgs_pair_b64
                
                else:
                    return "MSG RELAY SERVICE: message queue empty!"
                
        elif command == "getmsg":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            user, signed_msg_num = unpair(message_data)

            msg_num, signature = unpair(signed_msg_num)

            valid = False
            
            # verificar se a chave pública de utilizador valida a assinatura
            try:
                user_rsa_public_keys_dict[user].verify(
                    signature,
                    msg_num,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                valid = True

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error validating command signature!"
            
            if valid:
                print("Signature verified!")

                if user in message_queues.keys():
                    for i, message in enumerate(message_queues[user]):
                        if i == int(msg_num.decode()):

                            if user == message[5]:
                                sender = message[0].decode()
                                message_txt = message[3].decode()
                                return_message = f"Message from {sender}: {message_txt}"
                                updated_message = (message[0], message[1], message[2], message[3], message[4], message[5], True)
                                message_queues[user][i] = updated_message
                                return_message = str(return_message)

                                cypher = Cipher(algorithms.AES(user_derived_keys_dict[user]), modes.CTR(b'\0' * 16), default_backend())
                                encryptor = cypher.encryptor()
                                encrypted_message = encryptor.update(return_message.encode()) + encryptor.finalize()

                                return_signature = self.private_key.sign(
                                    encrypted_message,
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256()
                                )

                                signature_encrypted_message_pair = mkpair(return_signature, encrypted_message)

                                encrypted_message_64 = base64.b64encode(signature_encrypted_message_pair)

                                return b'msg ' + encrypted_message_64
                            
                            else:
                                return "MSG RELAY SERVICE: verification error!"

                    return "MSG RELAY SERVICE: unknown message!"
                
                else:
                    return "MSG RELAY SERVICE: message queue empty!"
            
        elif command == "help":
            return help_str

        else:
            return "MSG RELAY SERVICE: command error!"
        
        return None

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