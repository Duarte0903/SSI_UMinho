# Respostas das Questões

## Q1

Após a execução do comando indicado obtemos o seguinte output:

```powershell
    python  -c "import cryptography; print(cryptography.__version__)"
    42.0.2
```

Logo, a versão da biblioteca `cryptography` instalada é a 42.0.2.

# Relatório do Guião da Semana 2

- **wc.py:**
    1. É guardado o conteúdo do ficheiro na variável content.

    2. O número de linhas é calculado aplicando o método split("\n") à variável content. O número de linhas corresponde ao comprimento da lista resultante.

    3. O número de palavras é calculado aplicando o método split() à variável content. O número de palavras corresponde ao comprimento da lista resultante.

    4. Para calular as letras itera-se sobre cada caractere de content. Caso o caractere fizer parte do alfabeto, é adicionado à lista letters. O número de letras corresponde ao comprimento da lista calculada.