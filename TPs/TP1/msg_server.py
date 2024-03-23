import os
import re
import asyncio
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

help_str = "Usage:\n-user <FNAME>\tSpecify user data file (default: userdata.p12)\n" \
              "send <UID> <SUBJECT>\tSend a message\n" \
                "askqueue\tRequest unread messages\n" \
                "getmsg <NUM>\tRetrieve a specific message\n" \
                "help\tPrint this help message\n"

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
        self.user_public_keys = {}  # Dicionário para armazenar as chaves públicas dos utilizadores UID -> chave
        self.message_queues = {}    # Dicionário para armazenar as filas de mensagens dos utilizadores UID -> lista de mensagens
        self.timestamp_records = {} # Dicionário para armazenar os timestamps das mensagens dos utilizadores msg_cnt -> timestamp

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
                return "MSG RELAY SERVICE: command error!" + "\n" + help_str
        
        elif re.match(r'-(\w+)', command):
            return txt
               
        elif command == "public":
            public_key = parts[1].encode()
            self.user_public_keys[self.id] = serialization.load_pem_public_key(public_key)
            return "MSG RELAY SERVICE: public key received"

        elif command == "askqueue":
            pass

        elif command == "help":
            return help_str

        else:
            return "MSG RELAY SERVICE: command error!" + "\n" + help_str
        
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
