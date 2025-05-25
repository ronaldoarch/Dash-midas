import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sys
sys.path.append('..')
from app import app

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave_padrao_insegura')

# Handler para Vercel
def handler(environ, start_response):
    return app(environ, start_response) 