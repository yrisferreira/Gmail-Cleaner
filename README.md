# Gmail Cleaner

Um script em Python para limpar automaticamente emails spam do Gmail. O script usa a API do Gmail para identificar e mover emails spam para a lixeira com base em vários critérios.

## Funcionalidades

- ✨ Autenticação segura com OAuth 2.0
- 📧 Detecção inteligente de spam
- 🔍 Múltiplos critérios de análise:
  - Flags de spam existentes
  - Score de spam
  - Links de marketing/newsletter
  - Palavras-chave suspeitas
  - Domínios suspeitos
  - Caracteres especiais excessivos
  - Emails muito antigos
  - Assuntos muito longos
- 🗑️ Move spam para a lixeira (não deleta permanentemente)
- 📝 Sistema de logging detalhado

## Requisitos

- Python 3.6 ou superior
- Conta Google
- Credenciais do Google Cloud Platform

## Instalação

1. Clone o repositório:
```bash
git clone [URL_DO_SEU_REPOSITÓRIO]
cd gmail-cleaner
```

2. Instale as dependências:
```bash
pip3 install --break-system-packages -r requirements.txt
```

## Configuração

1. Acesse o [Google Cloud Console](https://console.cloud.google.com)
2. Crie um novo projeto
3. Ative a API do Gmail
4. Configure a tela de consentimento OAuth:
   - Escolha "Externo"
   - Adicione seu email como usuário de teste
   - Adicione o escopo: `https://www.googleapis.com/auth/gmail.modify`
5. Crie credenciais OAuth 2.0:
   - Tipo: Aplicativo para Desktop
   - Baixe o arquivo JSON
   - Renomeie para `credentials.json`
   - Coloque na pasta do projeto

## Uso

Execute o script:
```bash
python3 gmail_cleaner.py
```

Na primeira execução:
1. Uma página do navegador abrirá
2. Faça login com sua conta Google
3. Autorize o acesso
4. O script começará a processar seus emails

## Critérios de Spam

O script considera um email como spam se:
- Possui flag de spam
- Score de spam > 5
- Contém links de marketing/newsletter
- Contém palavras-chave suspeitas
- Vem de domínios suspeitos
- Tem muitos caracteres especiais
- É muito antigo (> 1 ano)
- Tem assunto muito longo

## Logs

O script gera logs detalhados em `gmail_cleaner.log` com:
- Progresso do processamento
- Emails identificados como spam
- Erros encontrados

## Segurança

- Usa OAuth 2.0 para autenticação segura
- Não armazena senhas
- Apenas move emails para a lixeira (possível recuperar)
- Credenciais armazenadas localmente

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para:
- Reportar bugs
- Sugerir melhorias
- Enviar pull requests

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes. 