from flask import Flask
import sys
sys.path.append('..')
from app import app

# Handler para Vercel
handler = app 