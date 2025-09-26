# Configuração das Credenciais do Trello

## Problema Identificado

O erro 500 (Internal Server Error) ao tentar abrir PDF, áudio e vídeo estava ocorrendo porque as credenciais do Trello não estavam configuradas corretamente.

## Solução

### 1. Obter Credenciais do Trello

1. Acesse: https://trello.com/app-key
2. Copie sua **API Key**
3. Clique em "Token" para gerar um **Token** de acesso
4. Copie o **Token** gerado

### 2. Configurar o arquivo .env

Edite o arquivo `.env` na raiz do projeto e configure:

```env
# Configurações do Trello (OBRIGATÓRIAS)
TRELLO_KEY=sua_api_key_aqui
TRELLO_TOKEN=seu_token_aqui
TRELLO_BOARD=id_do_seu_board
```

**IMPORTANTE:** 
- Use `TRELLO_KEY` (não `TRELLO_API_KEY`)
- Use `TRELLO_BOARD` (não `TRELLO_BOARD_ID`)
- Substitua os valores pelos reais obtidos no Trello

### 3. Reiniciar o Servidor

Após configurar o `.env`, reinicie o servidor Flask:

```bash
# Pare o servidor (Ctrl+C)
# Inicie novamente
python app.py
```

### 4. Verificar se Funcionou

1. Acesse a aplicação
2. Tente abrir um arquivo PDF, áudio ou vídeo
3. Se ainda der erro 500, verifique se:
   - As credenciais estão corretas
   - O arquivo `.env` está na raiz do projeto
   - O servidor foi reiniciado após a alteração

## Para Deploy no Render

No painel do Render, configure as variáveis de ambiente:

- `TRELLO_KEY` = sua_api_key_do_trello
- `TRELLO_TOKEN` = seu_token_do_trello  
- `TRELLO_BOARD` = id_do_seu_board

**Não faça deploy sem testar localmente primeiro!**