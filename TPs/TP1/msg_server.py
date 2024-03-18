import asyncio

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

# Defina uma estrutura de dados para armazenar as mensagens dos usuários
user_data = {}

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0

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
            # Implemente a lógica para mostrar instruções de uso
            pass
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
