# Guião S8

## Q1

Foi criada a diretoria q1/teste.txt. De seguida foram alteradas as permissões do ficheiro e da diretoria:

```bash
mkdir q1
touch q1/teste.txt

chmod u+rwx q1/teste.txt
chmod g+r q1/teste.txt
chmod o+r q1/teste.txt

chmod u+rwx q1
chmod g+r q1/teste.txt
chmod o+r q1/teste.txt

```

## Q2

Foram criados 3 utilizadores com password 123123:

```bash
sudo useradd colega1
sudo useradd colega2
sudo useradd colega3 

sudo passwd colegax
> 123123
```

Depois foram criados dois grupos:

```bash
sudo groupadd doiselementos
sudo groupadd todos
```

O colega1 e o colega2 foram adicionados ao doiselementos:

```bash 
sudo usermod -a -g doiselementos colega1
sudo usermod -a -g doiselementos colega2
``` 

De seguida todos os novos users foram adicionados ao grupo todos:

```bash
sudo usermod -a -g todos colega1
sudo usermod -a -g todos colega2
sudo usermod -a -g todos colega3
```

Iniciou-se de seguida sessão com o colega1:

```bash
su colega1
```

## Q3

Para realizar esta questão foi criado o programa `file_content.c`.

Após a compilação do programa, foram atribuidas as restições do owner do ficheiro

```bash
sudo chmod u+s file_content
```

O programa acabou por ser adicionado ao grupo doiselementos (colega1 e colega2)

```bash
sudo chgrp doiselementos file_content 
```

Agora é atribuida aos grupos associados ao programa permissão para executar.

```bash
sudo chmod g+x file_content
```

O colega3 não tem permissão para executar o programa pois não está no grupo doiselementos:

```bash
$ ./file_content q3.txt 
sh: 1: ./file_content: Permission denied
```

## Q4

Começou-se por definir com recurso a ACL uma permissão específica para o ficheiro `file_content.c`. O utilizador colega1 tem permissão de leitura, escrita e execução sobre este ficheiro.

```bash 
setfacl -m u:colega1:rwx file_content.c
```

Com recurso a ACL atribui-se também permissões sobre este ficheiro ao grupo doiselementos.

```bash
setfacl -m g:doiselementos:rw- file_content.c
```

Para validar as operações realizadas, recorreu-se ao comando `getacl`:

```bash
getfacl file_content.c
```

Obtemos assim o seguinte resultado:

```bash
# file: file_content.c
# owner: user
# group: user
user::rw-
user:colega1:rwx
group::rw-
group:doiselementos:rw-
mask::rwx
other::r--
```