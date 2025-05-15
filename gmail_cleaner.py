import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime, timedelta
import logging
import json
import re
from typing import Optional, Dict, Any, List
from email import utils as email_utils
import pytz

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gmail_cleaner.log'),
        logging.StreamHandler()
    ]
)

# Escopos necessários para a API do Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Palavras-chave que podem indicar spam
SPAM_KEYWORDS = [
    'oferta', 'promoção', 'desconto', 'ganhe', 'grátis',
    'lottery', 'winner', 'congratulations', 'prize',
    'urgent', 'urgente', 'importante', 'atenção',
    'milhões', 'dinheiro fácil', 'renda extra',
    'trabalhe de casa', 'oportunidade única',
    'cartão de crédito', 'empréstimo'
]

# Domínios comumente associados a spam
SPAM_DOMAINS = [
    'spam.com', 'marketing.com', 'ads.com',
    'promo.com', 'offer.com', 'deal.com'
]

def verify_credentials_file() -> bool:
    """Verifica se o arquivo de credenciais existe e é válido."""
    if not os.path.exists('credentials.json'):
        logging.error('Arquivo credentials.json não encontrado!')
        return False
    
    try:
        with open('credentials.json', 'r') as f:
            creds_data = json.load(f)
            required_keys = ['client_id', 'client_secret', 'auth_uri', 'token_uri']
            if not all(key in creds_data['installed'] for key in required_keys):
                logging.error('Arquivo de credenciais está incompleto ou malformado')
                return False
    except Exception as e:
        logging.error(f'Erro ao ler arquivo de credenciais: {e}')
        return False
    
    return True

def get_gmail_service() -> Optional[Any]:
    """Configura e retorna o serviço da API do Gmail."""
    if not verify_credentials_file():
        return None

    creds = None
    
    # Verifica se já existem tokens salvos
    if os.path.exists('token.pickle'):
        try:
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
            logging.info('Token existente carregado com sucesso')
        except Exception as e:
            logging.error(f'Erro ao carregar token: {e}')
            if os.path.exists('token.pickle'):
                os.remove('token.pickle')
                logging.info('Token inválido removido')
    
    # Se não há credenciais válidas, faz o login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logging.info('Atualizando credenciais expiradas...')
                creds.refresh(Request())
                logging.info('Credenciais atualizadas com sucesso')
            except Exception as e:
                logging.error(f'Erro ao atualizar credenciais: {e}')
                return None
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                logging.info('Novas credenciais obtidas com sucesso')
            except Exception as e:
                logging.error(f'Erro no processo de autenticação: {e}')
                return None
        
        # Salva as credenciais para o próximo uso
        try:
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
            logging.info('Credenciais salvas com sucesso')
        except Exception as e:
            logging.error(f'Erro ao salvar credenciais: {e}')

    try:
        service = build('gmail', 'v1', credentials=creds)
        logging.info('Serviço Gmail inicializado com sucesso')
        return service
    except Exception as e:
        logging.error(f'Erro ao criar serviço Gmail: {e}')
        return None

def extract_email_address(email_string: str) -> str:
    """Extrai o endereço de email de uma string."""
    match = re.search(r'[\w\.-]+@[\w\.-]+', email_string)
    return match.group(0) if match else ''

def parse_email_date(date_str: str) -> datetime:
    """Converte string de data do email para datetime com timezone."""
    try:
        # Primeiro tenta o formato RFC 2822
        email_date = email_utils.parsedate_to_datetime(date_str)
        if email_date:
            return email_date.astimezone(pytz.UTC)
    except Exception:
        pass
    
    try:
        # Tenta outros formatos comuns
        for fmt in [
            '%a, %d %b %Y %H:%M:%S %z',
            '%d %b %Y %H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S %z'
        ]:
            try:
                return datetime.strptime(date_str, fmt).astimezone(pytz.UTC)
            except ValueError:
                continue
    except Exception:
        pass
    
    # Se nada funcionar, retorna a data atual
    return datetime.now(pytz.UTC)

def is_spam(message: Dict[str, Any]) -> bool:
    """Verifica se um e-mail é spam baseado em critérios específicos."""
    try:
        headers = {header['name'].lower(): header['value'] 
                  for header in message['payload']['headers']}
        
        # Extrai informações importantes
        from_email = extract_email_address(headers.get('from', ''))
        subject = headers.get('subject', '').lower()
        
        # Processa a data com timezone
        received_date = parse_email_date(headers.get('date', ''))
        current_time = datetime.now(pytz.UTC)
        
        # Lista de critérios de spam
        spam_indicators = [
            # Flags de spam existentes
            'spam' in headers.get('x-spam-flag', '').lower(),
            float(headers.get('x-spam-score', '0')) > 5,
            
            # Verificação de marketing
            'marketing' in headers.get('list-unsubscribe', '').lower(),
            'newsletter' in headers.get('list-id', '').lower(),
            
            # Verificação de palavras-chave no assunto
            any(word in subject for word in SPAM_KEYWORDS),
            
            # Verificação de domínios suspeitos
            any(domain in from_email for domain in SPAM_DOMAINS),
            
            # Verificação de caracteres especiais excessivos no assunto
            len(re.findall(r'[!$%*#@]', subject)) > 3,
            
            # Emails muito antigos (mais de 1 ano)
            received_date < current_time - timedelta(days=365),
            
            # Emails com assuntos muito longos
            len(subject) > 150
        ]
        
        return any(spam_indicators)
    except Exception as e:
        logging.error(f'Erro ao analisar email: {e}')
        return False

def process_emails(service: Any, max_results: int = 500) -> None:
    """Processa os emails em lotes."""
    try:
        # Lista todos os e-mails
        results = service.users().messages().list(
            userId='me',
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])

        if not messages:
            logging.info('Nenhum e-mail encontrado.')
            return

        total_processed = 0
        spam_count = 0
        
        for message in messages:
            try:
                msg = service.users().messages().get(
                    userId='me', 
                    id=message['id']
                ).execute()
                
                total_processed += 1
                
                if is_spam(msg):
                    # Move para a lixeira em vez de deletar permanentemente
                    service.users().messages().trash(
                        userId='me', 
                        id=message['id']
                    ).execute()
                    spam_count += 1
                    logging.info(f'E-mail movido para lixeira: {message["id"]}')
                
                # Log de progresso a cada 10 emails
                if total_processed % 10 == 0:
                    logging.info(
                        f'Progresso: {total_processed}/{len(messages)} emails processados, '
                        f'{spam_count} spam encontrados'
                    )
                    
            except Exception as e:
                logging.error(f'Erro ao processar email {message["id"]}: {e}')
                continue

        logging.info(
            f'Processamento concluído!\n'
            f'Total de emails processados: {total_processed}\n'
            f'Total de spam removidos: {spam_count}'
        )

    except HttpError as error:
        logging.error(f'Erro na API do Gmail: {error}')
    except Exception as e:
        logging.error(f'Erro inesperado: {e}')

def clean_gmail() -> None:
    """Função principal para limpar o Gmail."""
    service = get_gmail_service()
    if not service:
        logging.error('Não foi possível iniciar o serviço do Gmail')
        return

    process_emails(service)

def main():
    """Função principal."""
    logging.info('Iniciando limpeza do Gmail...')
    clean_gmail()
    logging.info('Limpeza concluída!')

if __name__ == '__main__':
    main() 