import sys
sys.path.append('..')
from app import app

def handler(environ, start_response):
    return app(environ, start_response) 