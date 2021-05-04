from concurrent import futures
import kolesa_pb2
import kolesa_pb2_grpc
import grpc
import requests
from bs4 import BeautifulSoup
import logging
import datetime
import sys
import os
import json
from logging.handlers import TimedRotatingFileHandler
import re


FORMATTER = logging.Formatter("%(asctime)s — %(levelname)s — %(message)s")

date = datetime.date.today().strftime('%Y%m%d')


FIRST = True
dirname = os.path.dirname(__file__)



dirname = os.path.join(dirname,'logs')

if not os.path.exists(dirname):
    os.mkdir(dirname)

LOG_FILE = os.path.join(dirname,'my_app.'+date+'.log')

def getFirst():
    global FIRST
    return FIRST
def setFirst(state):
    global FIRST
    FIRST = state
def getDate():
    global date
    return date   

def namer(name):

    a = name[-28:][-8:]
    date = datetime.datetime.strptime(a,'%Y%m%d').date()
    date = date + datetime.timedelta(days=1)
    str_date = datetime.datetime.strftime(date,'%Y%m%d')
    name = name.replace('.'+getDate()+'.log','') + '.log'
    return name.replace(a,str_date)


def get_console_handler():
   console_handler = logging.StreamHandler(sys.stdout)
   console_handler.setFormatter(FORMATTER)
   return console_handler
def get_file_handler():
   file_handler = TimedRotatingFileHandler(LOG_FILE,when='midnight',backupCount=10,encoding='utf-8')
   file_handler.suffix = '%Y%m%d'
   file_handler.namer =namer
   file_handler.extMatch = re.compile(r"^\d{8}$") 


   file_handler.setFormatter(FORMATTER)
   return file_handler
def get_logger(logger_name):
   logger = logging.getLogger(logger_name)
   logger.setLevel(logging.DEBUG) # better to have too much log than not enough
   logger.addHandler(get_console_handler())
   logger.addHandler(get_file_handler())
   # with this pattern, it's rarely necessary to propagate the error up to parent
   logger.propagate = False
   return logger

logger = get_logger('Adil')

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

def getVirusLinks(phone):
    headers = {
        'authority': 'www.virustotal.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"',
        'x-tool': 'vt-ui-main',
        'sec-ch-ua-mobile': '?0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'content-type': 'application/json',
        'x-app-version': 'v1x15x0',
        'accept': 'application/json',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'x-vt-anti-abuse-header': 'MTc5NjIwOTYwNjktWkc5dWRDQmlaU0JsZG1scy0xNjIwMTAzOTY3LjAzOQ==',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.virustotal.com/',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'cookie': '_ga=GA1.2.188280054.1617721649; _gid=GA1.2.1811885991.1620103948; _gat=1',
    }

    params = (
        ('limit', '20'),
        ('relationships[comment]', 'author,item'),
        ('query', f'https://{phone}/'),
    )

    response = requests.get('https://www.virustotal.com/ui/search', headers=headers, params=params)
    soup = BeautifulSoup(response.content, 'html.parser')
    result = json.loads(soup.text)
    out = []
    for i in result['data']:
        x = i['attributes']['last_analysis_stats']
        link = kolesa_pb2.Link()
        link.url = f'{phone}'
        link.label = f'{x}'
        out.append(link)
    return out


class KolesaScraperServicer(kolesa_pb2_grpc.KolesaScraperServicer):

    def LoadVirusLinks(self, request, context):
        logger.info('Reply response for ' + request.phone)
        response = kolesa_pb2.LinksReply()
        response.links.extend(getVirusLinks(request.phone))
        return response

def serve():
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'config.json')
    file1 = open(filename,'r')
    json_parsed = json.loads(file1.read())
    try:
        max_workers = int(json_parsed['max_workers'])
    except ValueError:
        logger.error('Max_workers is not valid please change that in config.json')
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    kolesa_pb2_grpc.add_KolesaScraperServicer_to_server(KolesaScraperServicer(),server)
    server.add_insecure_port('[::]:'+json_parsed['port'])
    server.start()
    logger.info('Server started at ' +  ' Listening port 8080')
    server.wait_for_termination()




if __name__ == '__main__':
    serve()