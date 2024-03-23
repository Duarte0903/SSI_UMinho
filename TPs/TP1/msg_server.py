import os
import asyncio
from cryptography.hazmat.primitives.serialization import pkcs12

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

# Defina uma estrutura de dados para armazenar as mensagens dos usuários
user_data = {}

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key, self.user_cert, self.ca_cert = get_userdata("projCA/MSG_SERVER.p12")

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        txt = msg.decode().strip()
        print('%d : %r' % (self.id, txt))
        parts = txt.split(' ')
        command = parts[0]
        if command == "send":
            if len(parts) < 3:
                return "Erro: Comando send requer <UID> <SUBJECT>"
            
            # Obtém o UID do destinatário e o assunto da mensagem
            uid = parts[1]
            subject = ' '.join(parts[2:])
            
            # Lê o conteúdo da mensagem do stdin
            print("Escreva a mensagem (limite de 1000 bytes): ")
            message = input()[:1000]

            # Armazena a mensagem no dicionário de dados do utilizador
            if uid not in user_data:
                user_data[uid] = []
            user_data[uid].append((subject, message))
            return "Mensagem enviada e armazenada com sucesso!"
        
        elif command == "-user":
            # Implemente a lógica para tratar a opção -user
            pass
        elif command == "askqueue":
            # Implemente a lógica para solicitar a lista de mensagens não lidas
            pass
        elif command == "getmsg":
            # Implemente a lógica para obter uma mensagem específica
            pass
        elif command == "help":
            return b"Usage:\n-user <FNAME>\tSpecify user data file (default: userdata.p12)\n" \
                    b"send <UID> <SUBJECT>\tSend a message\n" \
                    b"askqueue\tRequest unread messages\n" \
                    b"getmsg <NUM>\tRetrieve a specific message\n" \
                    b"help\tPrint this help message\n"
    
        else:
            return "Comando desconhecido"
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
        if response:
            writer.write(response.encode())
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
