# Projecto de Criptografia Aplicada (TP1)

## Indice

- [Iniciar o clientes e o servidor](#iniciar-os-clientes-e-servidor)
    - [Validação de certificados](#certificados)
- [Enviar mensagens](#enviar-mensagens)
- [Queue de mensagens](#queue-de-mansagens)
- [Ver mensagens](#ver-mensagens)

## <a id="iniciar-os-clientes-e-servidor">Iniciar o clientes e o servidor</a>

Para iniciar corretamente um **cliente** é necessário usar o comando -user. Este comando tem como argumento o UID do cliente e, opcionalmente, o path do ficheiro userdata.p12. Caso seja apenas inserido o UID, será carregado o ficheiro com o mesmo nome na localização default dos ficheiros.

Do ficheiro userdata.p12 são extraidos a chave privada, o certificado do cliente e o certificado da CA. Posteriormente será gerada a chave pública a partir da chave privada.

Agora é necessário gerar as chaves DH (Diffie–Hellman). Para tal são usados os parâmetros p e g (mesmos usados nos guiões). Estes parâmetros foram hard-coded para evitar esperas na geração de parâmetros DH durante o desenvolvimento. O cliente pode então gerar a chave privada DH e a partir dela a chave pública DH.

O cliente procede agora com o envio da sua chave publica DH para o servidor junto do seu pseudonym extraido do seu certificado. Vale a pena mencionar que para os bytes de elementos relevantes das mensagens, é feito encoding usando Base64. Para enviar a chave pública DH, a mensagem começa com `user_pub_key` para que o servidor a processe devidamente.

Já no **servidor**, depois de este ter sido iniciado de forma semelhante ao cliente, a chave pública DH do cliente vai ser guardada num dicionário onde a key é o seu pseudonym. O servidor irá agora proceder com o envio da sua chave pública DH, uma assinatura, com a chave pública DH do servidor e do cliente, e o seu certificado. A assinatura é gerada com a chave privada do servidor. Esta mensagem começa com `server_key`.

O cliente deve agora validar o certificado do servidor e partir dele extrair e armazenar a sua chave pública. O cliente pode agora validar a assinatura enviada pelo servidor com recurso à chave pública que extraiu. Este irá ainda armazenar a chave pública DH do servidor.

Caso o certificado e a assinatura do servidor sejam válidos, cliente pode gerar a chave partilhada fazendo a troca de chaves entre a sua chave privada DH e a chave pública DH do servidor. Posteriormente pode gerar a chave derivada através da chave partilhada. Com isto feito, o client irá enviar de volta para o servidor o seu certificado e uma assinatura com a chave pública DH do cliente e a chave pública DH do servidor. Esta mensagem irá começar com `user_cert`.

De volta ao servidor, será agora validado o certificado do cliente e a partir dele será extraida e armazenada a sua chave pública. Caso a verificação da assinatura enviada posteriormente pelo cliente seja verificada pela chave pública do cliente, a fase de handshake está terminada e podemos proceder ao envio de mensagens.

### <a id="certificados">Validação de certificados</a>

Para a validação dos certificados foi utilizado o código fornecido no Guião S7 com algumas alterações. A função `valida_cert` recebe o certificado a validar e o seu subject. Primeiramente verifica se o certificado foi emitido pela CA. Irá depois verificar se tem validade. De seguida verifica os atributos do campo subject. Finalmente valida as extensões do certificado. Se nenhum destes procedimentos lançar um erro, o certificado é válido.

## <a id="enviar-mensagens">Enviar mensagens</a>

O envio de mensagens começa com a utilização do comando `send <uid> <subject>` no cliente. É depois pedido para introduzir o conteúdo da mensagem a enviar. Como o tamanho das mensagens está limitado a 1000 bytes, o cliente irá verificar o tamanho. Se este exceder o limite, a mensagem poderá ser introduzida de novo. Caso contrário a mensagem será encriptada com recurso à chave derivada e será gerada uma assinatura com a mensagem encriptada. Será então enviado para o servidor o uid do destinatário, o subject, a mensagem encriptada, a assinatura e o pseudonym do cliente que envia a mensagem. Esta mensagem irá começar com `send`.

No servidor, com recurso ao pseudonym, é possivel ir búscar a chave publica armazenada anteriormente para verificar a assinatura da mensagem envidada. Caso esta seja válida, é possivel desencriptar a mensagem com a chave derivada do cliente que enviou a mensagem (esta pode ser acedida com recurso ao pseudonym).

O servidor deve agora proceder com o armazenamento da mensagem na message queue do cliente especificado no uid. A mensagem será guardada na forma de um tuplo que contém o sender, timestamp, subject, mensagem, assinatura, uid e um boleano que diz que a mensagem foi lida ou não.

Irá por fim ser enviada uma confirmação ao cliente que enviou a mensagem a dizer que a mensagem foi enviada e guardada com sucesso.

## <a id="queue-mensagens">Queue de mensagens</a>

Para um cliente poder ver a sua message queue, deve usar o comando `askqueue`. Este comando irá enviar uma mensagem com o pseudonym do cliente em questão acompanhado por uma assinatura gerada com o mesmo. A mensagem enviada ao servidor irá começar com `askqueue`.

O servidor irá verificar a assinatura com a chave pública do cliente que pode ser obetida com recurso ao pseudonym. Caso a assinatura seja verificadak, o servidor irá juntar numa lista as mensagens onde o boleano seja False. Esta lista será convertida para string e encriptada com a chave derivada do cliente. A string encriptada será enviada juntamente com uma assinatura do servidor numa mensagem que começa com `user_queue`.

O cliente irá receber a mensagem, verificar a assinatura do servidor e desencriptar com a chave derivada, podendo assim ver a sua message queue.

## <a id="ver-mensagens">Ver mensagens</a>

Para que um cliente possa ver uma mensagem em específico deve usar o comando `getmsg <msg_num>`. O pedido è feito de forma semelhante ao comando `askqueue`. É gerada uma assinatura com o número da mensagem que se pretende e é por fim enviada uma mensagem para o servidor com o pseudonym, o número da mensagem e a assinatura. Esta mensagem começar com `getmsg`.

No servidor é verificada a assinatura e é procurada a mensagem. Da mensagem guardada são extraidos o sender e a menssagem em si. O boleano passa a ser True visto que a mensagem vai passar a estar lida. O servidor envia por fim a sua assinatura juntamente com a mensagem encriptada que contém o sender e a mensagem. Esta mensagem começa por `msg`.

O cliente vai receber a mensagem, verificar a assinatura do servidor e desencriptar com a chave derivada. A mensagem desencriptada será depois exposta ao utilizador.

##

**Nota:** Os comandos `send`, `askqueue` e `getmsg` rquerem que o cliente esteja autenticado. 