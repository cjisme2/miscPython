from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
import logging
import os
import base64
from openai import OpenAI
from datetime import datetime
'''
A quick poc framework that could be used to monitor a mailbox that receives unwanted mail and
then replies to the reporter our appreciation. Also added some AI capabilites for no reason
besides wanting to.

Important note in this we are only looking at the email that is sent for the reporting of the suspicous email
not the contents of the forwarded suspicous email

This requires a Google oauth token and a openai api
This was hobbled together the old fashion way, with caffeine, web searches and print statements.
'''

with open("openai_secret_key.txt","r") as file:
    OPENAI_API_KEY = file.read()
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
logger = logging.getLogger(__name__)
logging.basicConfig(filename='thanks4this.log', level=logging.INFO)

def get_credentials():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds


def fetch_emails(max_results):
    service = build('gmail', 'v1', credentials=get_credentials())
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread", maxResults=max_results).execute()
    messages = results.get('messages', [])

    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        subject,sender,fulldetails=parse_email_details(msg)
        category=categorize_email(subject,sender)
        print (category)
        if category == "CEO":
            message_text = """Thank you for reporting this CEO fraud
            we appreciate it
            """
            print (message_text)
        elif category == "Phish":
            message_text = """Thank you for reporting this unwanted email.  
            We will add it to our spam filtering list.
            \o/
            """
            print (message_text)
        elif category == "Incident":
            message_text = """Thank you for reporting this 
            we are investigating and will be in contact with you shortly.
            """
            print (message_text)
    
        else:   
            input("about to craft a response. Press any key to continue")
            message_text=generate_reply(subject,fulldetails)
            print(message_text)
        #uncomment when ready
        #send_email(service, sender, subject, message_text)
        

def parse_email_details(msg):
    headers = msg['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    sender = next(header['value'] for header in headers if header['name'] == 'From')
    fulldetails = get_email_body(msg)
    #print(fulldetails)
    return(subject,sender,fulldetails)

def get_email_body(msg):
    if 'parts' in msg['payload']:
        return get_text_from_parts(msg['payload']['parts'])
    else:
        return get_text_from_part(msg['payload'])

def get_text_from_parts(parts):
    text = ""
    for part  in parts:
        if part['mimeType'] == 'text/plain':
            text += get_text_from_part(part)
        elif part['mimeType'] == 'text/html':
            text += get_text_from_html(part)
    return text

def get_text_from_part(part):
    if 'data' in part['body']:
        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
    return ""

def get_text_from_html(part):
    html = get_text_from_part(part)
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text()


def print_email_details(msg):
    headers = msg['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    sender = next(header['value'] for header in headers if header['name'] == 'From')
    body = get_email_body(msg)

    print(f"Subject: {subject}")
    print(f"From: {sender}")
    print(f"Body: {body[:100]}...") # Print first 100 characters of the body
    print("-" * 50)


def categorize_email(subject, sender):
    subject = subject.lower()
    if "Spam" in subject:
        return "Spam"
    elif "Clicked" in sender:
        return "incident"
    elif "CEO" in sender:
        return "CEO"
    else:
        return "generate_reply"
    

def generate_reply(subject, body):
    client = OpenAI(api_key=OPENAI_API_KEY)
    prompt = f"""You are an assistant helping with email responses.
Email subject: {subject}
Email body: {body}
Write a short, professional reply to this email. If a reply is not appropriate, return a nice thank you for bringing this to our attention reply."""
  
    response = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[{"role": "user", "content": prompt}],
        # temperature=0.4
    )
    reply = response.choices[0].message.content.strip()
    return reply

def send_email(service, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = "Re: " + subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId='me', body={'raw': raw}).execute()
    

def main():
    logger.info('Started')
    try:
        fetch_emails(1)
    except Exception as e:
        print(e)
        input("An error has occured, please exit the window and restart the program...")
    logger.info('Finished')

if __name__ == '__main__':
    main()

    
