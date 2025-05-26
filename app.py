import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
from werkzeug.utils import secure_filename
from fpdf import FPDF
import gspread
from gspread_dataframe import get_as_dataframe
from google.oauth2.service_account import Credentials
import csv
import locale
import json
from datetime import datetime, timedelta
import openai
import unicodedata
from functools import wraps
from flask import abort

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'chave_insegura')

# Configuração do banco de dados
# Use DATABASE_URL para produção (ex: PostgreSQL), senão usa SQLite local
if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração para uploads externos (S3)
S3_BUCKET = os.environ.get('S3_BUCKET')
S3_KEY = os.environ.get('S3_KEY')
S3_SECRET = os.environ.get('S3_SECRET')
S3_REGION = os.environ.get('S3_REGION')

# Se todas as variáveis S3 estiverem presentes, ativa uso de S3
USE_S3 = all([S3_BUCKET, S3_KEY, S3_SECRET, S3_REGION])
if USE_S3:
    import boto3
    s3_client = boto3.client(
        's3',
        aws_access_key_id=S3_KEY,
        aws_secret_access_key=S3_SECRET,
        region_name=S3_REGION
    )

# Inicializa DB e Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ------------------- MODELOS ------------------- #
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class MetaConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    app_id = db.Column(db.String(255))
    app_secret = db.Column(db.String(255))
    access_token = db.Column(db.Text)
    webhook_url = db.Column(db.String(500), nullable=True)

# ------------------- LOGIN ------------------- #
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form

        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Faça login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for('config'))
        flash('Credenciais inválidas.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------- CONFIG META ------------------- #
@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        if not meta:
            meta = MetaConfig(user_id=current_user.id)
        meta.app_id = request.form['app_id']
        meta.app_secret = request.form['app_secret']
        meta.access_token = request.form['access_token']
        meta.webhook_url = request.form.get('webhook_url', None)
        db.session.add(meta)
        db.session.commit()
        flash('Dados salvos com sucesso.')
        return redirect(url_for('contas'))
    return render_template('config.html', meta=meta)

# ------------------- CONTAS / DASHBOARD ------------------- #
@app.route('/contas')
@login_required
def contas():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    if not meta or not meta.access_token:
        flash('Token não configurado.')
        return redirect(url_for('config'))

    try:
        response = requests.get(
            'https://graph.facebook.com/v19.0/me/adaccounts',
            params={'access_token': meta.access_token}
        )
        data = response.json()

        if 'error' in data:
            flash('Erro na API: ' + data['error']['message'])
            return redirect(url_for('config'))

        contas_data = data.get('data', [])

        contas_formatadas = []
        for conta in contas_data:
            conta_id = conta.get('id')
            nome = conta.get('name', 'Sem nome')
            business = requests.get(
                f"https://graph.facebook.com/v19.0/{conta_id}",
                params={'fields': 'business', 'access_token': meta.access_token}
            ).json()
            bm_nome = business.get('business', {}).get('name', 'Desconhecido')
            contas_formatadas.append({
                'id': conta_id,
                'nome': nome,
                'business': bm_nome
            })

        return render_template('contas.html', contas=contas_formatadas)

    except Exception as e:
        flash('Erro ao buscar contas: ' + str(e))
        return redirect(url_for('config'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    mensagem_sem_dados = False
    alcance = 0  # Inicializa alcance no início da função para evitar UnboundLocalError
    conversoes = 0  # Inicializa conversoes no início da função para evitar UnboundLocalError
    cpl = 0  # Inicializa cpl no início da função para evitar UnboundLocalError
    sugestoes = []
    positivos = []
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    if not meta or not meta.access_token:
        flash('Token não configurado.')
        return render_template(
            'dashboard.html',
            contas=[],
            campanhas=[],
            dados={},
            start_date=None,
            end_date=None,
            saldo_disponivel=None,
            alerta_saldo=None,
            saude_score=0,
            is_cassino=False,
            sugestoes=sugestoes,
            positivos=positivos
        )
    # Buscar contas de anúncio
    try:
        contas_resp = requests.get(
            'https://graph.facebook.com/v19.0/me/adaccounts',
            params={'access_token': meta.access_token, 'fields': 'id,name'}
        )
        contas_data = contas_resp.json().get('data', [])
        if 'error' in contas_resp.json():
            flash('Erro na API Meta: ' + contas_resp.json()['error'].get('message', ''))
            print('ERRO API META:', contas_resp.json())
            return render_template(
                'dashboard.html',
                contas=[],
                campanhas=[],
                dados={},
                start_date=None,
                end_date=None,
                saldo_disponivel=None,
                alerta_saldo=None,
                saude_score=0,
                is_cassino=False,
                sugestoes=sugestoes,
                positivos=positivos
            )
    except Exception as e:
        flash('Erro ao buscar contas da Meta: ' + str(e))
        print('ERRO EXCEÇÃO CONTAS META:', e)
        return render_template(
            'dashboard.html',
            contas=[],
            campanhas=[],
            dados={},
            start_date=None,
            end_date=None,
            saldo_disponivel=None,
            alerta_saldo=None,
            saude_score=0,
            is_cassino=False,
            sugestoes=sugestoes,
            positivos=positivos
        )
    conta_id = request.args.get('conta_id') or (contas_data[0]['id'] if contas_data else None)
    campanhas = []
    campanha_id = request.args.get('campanha_id')
    metricas = {}
    nome_campanha = ''
    saldo_disponivel = None
    alerta_saldo = None
    # Filtro de datas
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    # --- NOVO BLOCO: MÉTRICAS AGREGADAS DA CONTA ---
    metricas_conta = {}
    if conta_id:
        # Lista de contas de cassino fornecida pelo usuário
        contas_cassino = [
            'jhon', 'brasil boloes', 'roleta vip', 'conta lucas', 'brazzo bet', 'top cash', 'el salvador', 'bm el salvador'
        ]
        contas_normais = [
            'rs motos', 'agulha magica', 'karine', 'casal do milhao', 'fabio', 'atmo'
        ]
        nome_conta = None
        for c in contas_data:
            if c['id'] == conta_id:
                nome_conta = c.get('name', '').strip().lower()
                break
        is_cassino = False
        nome_conta_normalizado = normalizar_nome(nome_conta)
        for nome in contas_cassino:
            if normalizar_nome(nome) in nome_conta_normalizado:
                is_cassino = True
                break
        # Buscar campanhas da conta
        campanhas_resp = requests.get(
            f'https://graph.facebook.com/v19.0/{conta_id}/campaigns',
            params={'access_token': meta.access_token, 'fields': 'id', 'limit': 50}
        )
        campanhas = campanhas_resp.json().get('data', [])
        # Inicializar agregadores
        total_impressao = 0
        total_cliques = 0
        total_investimento = 0
        total_clientes = 0
        for campanha in campanhas:
            campanha_id_tmp = campanha['id']
            url = f'https://graph.facebook.com/v19.0/{campanha_id_tmp}/insights'
            params = {
                'access_token': meta.access_token,
                'fields': 'impressions,clicks,spend,actions',
            }
            if start_date and end_date:
                params['time_range'] = f'{{"since":"{start_date}","until":"{end_date}"}}'
            else:
                params['date_preset'] = 'last_30d'
            response = requests.get(url, params=params)
            data = response.json()
            insights_list = data.get('data', [])
            insights = insights_list[0] if insights_list else {}
            total_impressao += int(insights.get('impressions', 0) or 0)
            total_cliques += int(insights.get('clicks', 0) or 0)
            total_investimento += float(insights.get('spend', 0) or 0)
            # Buscar clientes (FTD ou lead)
            if 'actions' in insights:
                for a in insights['actions']:
                    if is_cassino:
                        if a['action_type'] == 'offsite_conversion.fb_pixel_purchase':
                            total_clientes += int(a['value'])
                    else:
                        if a['action_type'] in ['lead', 'offsite_conversion.lead']:
                            total_clientes += int(a['value'])
        # Calcular métricas finais
        cpm = (total_investimento / total_impressao * 1000) if total_impressao else 0
        ctr = (total_cliques / total_impressao * 100) if total_impressao else 0
        cpc = (total_investimento / total_cliques) if total_cliques else 0
        cac = (total_investimento / total_clientes) if total_clientes else 0
        metricas_conta = {
            'cpm': cpm,
            'ctr': f"{ctr:.2f}%" if total_impressao else '-',
            'cac': cac,
            'quantidade_clientes': total_clientes,
            'investimento': total_investimento,
            'cliques': total_cliques,
            'cpc': cpc
        }
    if conta_id:
        # Buscar saldo disponível da conta
        conta_info_resp = requests.get(
            f'https://graph.facebook.com/v19.0/{conta_id}',
            params={'access_token': meta.access_token, 'fields': 'balance'}
        )
        conta_info = conta_info_resp.json()
        saldo_disponivel = conta_info.get('balance')
        account_status = conta_info.get('account_status')
        nome_conta = None
        for c in contas_data:
            if c['id'] == conta_id:
                nome_conta = c['name']
                break
        # Alerta de saldo baixo ou cartão recusado
        if saldo_disponivel is not None and float(saldo_disponivel)/100 <= 30:
            alerta_saldo = f'Atenção: saldo disponível para anúncios na conta "{nome_conta}" está abaixo de R$ 30,00!'
        if account_status is not None and int(account_status) != 1:
            alerta_saldo = f'Atenção: Cartão recusado ou conta "{nome_conta}" com restrição de pagamento!'
        # Buscar campanhas da conta
        campanhas_resp = requests.get(
            f'https://graph.facebook.com/v19.0/{conta_id}/campaigns',
            params={'access_token': meta.access_token, 'fields': 'id,name', 'limit': 50}
        )
        campanhas = campanhas_resp.json().get('data', [])
        if campanhas:
            if not campanha_id:
                campanha_id = campanhas[0]['id']
            for c in campanhas:
                if c['id'] == campanha_id:
                    nome_campanha = c['name']
                    break
        # Buscar métricas da campanha
        if campanha_id:
            cpl = 0
            cpr = 0
            conversoes = 0
            alcance = 0
            ctr = '-'
            url = f'https://graph.facebook.com/v19.0/{campanha_id}/insights'
            params = {
                'access_token': meta.access_token,
                'fields': 'impressions,reach,clicks,spend,actions,cost_per_action_type',
            }
            if start_date and end_date:
                params['time_range'] = f'{{"since":"{start_date}","until":"{end_date}"}}'
            else:
                params['date_preset'] = 'last_30d'
            try:
                response = requests.get(url, params=params)
                data = response.json()
                print('DEBUG PDF - Dados retornados:', data)
                insights_list = data.get('data', [])
                insights = insights_list[0] if insights_list else {}
                impressoes = int(insights.get('impressions', 0) or 0)
                alcance = int(insights.get('reach', 0) or 0)
                cliques = int(insights.get('clicks', 0) or 0)
                gasto = float(insights.get('spend', 0) or 0)
                conversoes = 0
                cpl = 0
                cpr = 0
                # Buscar clientes (FTD ou lead) para a campanha
                if 'actions' in insights:
                    for a in insights['actions']:
                        if is_cassino:
                            if a['action_type'] == 'offsite_conversion.fb_pixel_purchase':
                                conversoes += int(a['value'])
                        else:
                            if a['action_type'] in [
                                'link_click',
                                'onsite_conversion.messaging_conversation_started_7d',
                                'onsite_conversion.messaging_first_reply',
                                'onsite_conversion.pre_add_to_cart',
                                'onsite_conversion.initiated_checkout',
                                'onsite_conversion.add_to_cart',
                                'onsite_conversion.purchase',
                                'offsite_conversion.fb_pixel_purchase',
                                'lead',
                                'offsite_conversion.lead',
                                'contact',
                                'onsite_conversion.lead_grouped',
                                'onsite_conversion.submit_application',
                                'onsite_conversion.schedule',
                                'onsite_conversion.add_payment_info',
                                'onsite_conversion.start_trial',
                                'onsite_conversion.subscribe',
                                'onsite_conversion.complete_registration',
                                'onsite_conversion.search',
                                'onsite_conversion.view_content'
                            ]:
                                conversoes += int(a['value'])
                if conversoes > 0:
                    cpl = gasto / conversoes
                    cpr = cpl
                ctr = f"{(cliques/impressoes*100):.2f}%" if impressoes else '-' 
                # Calcular score de saúde
                score = 0
                # CPL
                if cpl and cpl <= 3:
                    score += 30
                elif cpl and cpl <= 5:
                    score += 20
                elif cpl:
                    score += 5
                # Conversões
                if conversoes and conversoes > 100:
                    score += 20
                elif conversoes and conversoes >= 10:
                    score += 10
                # Alcance
                if alcance and alcance > 50000:
                    score += 15
                elif alcance and alcance >= 10000:
                    score += 10
                # CTR
                try:
                    ctr_val = float(ctr.replace('%','')) if ctr and ctr != '-' else 0
                except:
                    ctr_val = 0
                if ctr_val > 3:
                    score += 15
                elif ctr_val >= 1:
                    score += 10
                # Saldo disponível
                saldo_float = float(saldo_disponivel)/100 if saldo_disponivel else 0
                if saldo_float > 100:
                    score += 10
                elif saldo_float >= 30:
                    score += 5
                saude_score = min(int(score * 100 / 90), 100)  # normaliza para 0-100
                # Atualizar dicionário de métricas para o dashboard
                resultados = conversoes  # Para contas normais, resultados = conversoes
                metricas = {
                    'conta_id': conta_id,
                    'campanha_id': campanha_id,
                    'nome_campanha': nome_campanha,
                    'cliques': cliques,
                    'impressoes': impressoes,
                    'quantidade_clientes': conversoes,
                    'cac': cac,
                    'investimento': gasto,
                    'cpc': cpc,
                    'pm': alcance,
                    'ctr': ctr,
                    'resultados': resultados if not is_cassino else None,
                    'start_date': start_date,
                    'end_date': end_date,
                    'saude_score': saude_score
                }
            except Exception as e:
                flash('Erro ao buscar métricas do Meta: ' + str(e))
        # Calcular score de saúde
        score = 0
        # CPL
        if cpl and cpl <= 3:
            score += 30
        elif cpl and cpl <= 5:
            score += 20
        elif cpl:
            score += 5
        # Conversões
        if conversoes and conversoes > 100:
            score += 20
        elif conversoes and conversoes >= 10:
            score += 10
        # Alcance
        if alcance and alcance > 50000:
            score += 15
        elif alcance and alcance >= 10000:
            score += 10
        # CTR
        try:
            ctr_val = float(ctr.replace('%','')) if ctr and ctr != '-' else 0
        except:
            ctr_val = 0
        if ctr_val > 3:
            score += 15
        elif ctr_val >= 1:
            score += 10
        # Saldo disponível
        saldo_float = float(saldo_disponivel)/100 if saldo_disponivel else 0
        if saldo_float > 100:
            score += 10
        elif saldo_float >= 30:
            score += 5
        saude_score = min(int(score * 100 / 90), 100)  # normaliza para 0-100
    cpl = 0  # Inicializa cpl para evitar UnboundLocalError nas sugestões
    # --- SUGESTÕES PREDITIVAS PARA O DASHBOARD ---
    sugestoes = []
    positivos = []
    cac = metricas.get('cac', 0) if metricas else 0
    quantidade_clientes = metricas.get('quantidade_clientes', 0) if metricas else 0
    ctr = metricas.get('ctr', '-')
    try:
        ctr_val = float(ctr.replace('%','')) if ctr and ctr != '-' else 0
    except:
        ctr_val = 0
    investimento = metricas.get('investimento', 0) if metricas else 0
    impressoes = metricas.get('impressoes', 0) if metricas else 0
    pm = metricas.get('pm', 0) if metricas else 0
    cpc = metricas.get('cpc', 0) if metricas else 0
    # CAC/CPL
    if cac and cac <= 5:
        positivos.append('Excelente CAC/CPL. Continue otimizando para manter esse resultado.')
    elif cac and cac > 15:
        sugestoes.append('O CAC/CPL está alto. Considere revisar segmentação, criativos e oferta. Teste públicos diferentes e otimize anúncios de baixo desempenho.')
    elif cac:
        sugestoes.append('O CAC/CPL está dentro da média, mas pode ser melhorado. Experimente pequenas mudanças em criativos ou segmentação.')
    # Clientes/Leads
    if quantidade_clientes > 50:
        positivos.append('Ótima quantidade de clientes/leads para o período!')
    elif quantidade_clientes < 5 and quantidade_clientes > 0:
        sugestoes.append('Poucos clientes/leads convertidos. Analise o funil de cadastro, revise a oferta e teste abordagens diferentes para aumentar conversão.')
    # CTR
    if ctr_val < 1.0:
        sugestoes.append('CTR baixo. Teste banners e criativos mais chamativos, ajuste chamadas para ação e avalie se o público está bem segmentado.')
    elif ctr_val > 5.0:
        positivos.append('CTR excelente! Seus anúncios estão atraentes para o público.')
    elif ctr_val < 2.0 and ctr_val > 0:
        sugestoes.append('CTR abaixo do ideal. Considere testar novos formatos de anúncio e revisar o texto das campanhas.')
    # Investimento x Conversão
    if investimento > 1000 and quantidade_clientes < 10:
        sugestoes.append('Investimento alto e poucos clientes. Avalie o ROI, reduza orçamento em campanhas pouco performáticas e foque nos melhores anúncios.')
    elif investimento < 200 and quantidade_clientes > 20:
        positivos.append('Ótima eficiência: muitos clientes com baixo investimento!')
    # Impressões e Alcance (para contas normais)
    if not is_cassino:
        if impressoes < 10000:
            sugestoes.append('Poucas impressões. Amplie o orçamento ou aumente o público para gerar mais visibilidade.')
        if pm < 5000:
            sugestoes.append('Alcance baixo. Tente expandir a segmentação ou aumentar o investimento.')
        if impressoes > 100000 and quantidade_clientes < 10:
            sugestoes.append('Muitas impressões, mas poucas conversões. Reveja a oferta, criativos e segmentação.')
    # PM (para cassinos)
    if is_cassino:
        if pm < 5000:
            sugestoes.append('Poucas pessoas alcançadas. Considere aumentar o orçamento ou expandir o público.')
        if pm > 50000 and quantidade_clientes < 10:
            sugestoes.append('Muitas pessoas alcançadas, mas poucas conversões. Teste novas ofertas ou revise o funil de cadastro.')
    # CPC
    if cpc > 3:
        sugestoes.append('CPC alto. Tente melhorar a relevância dos anúncios e a segmentação.')
    elif cpc < 0.5 and cpc > 0:
        positivos.append('CPC muito baixo! Excelente eficiência nos cliques.')
    # Sempre pelo menos uma sugestão
    if not sugestoes:
        sugestoes.append('Continue testando novos criativos, públicos e ofertas para manter ou melhorar a performance, mesmo com resultados excelentes.')
    if mensagem_sem_dados:
        resultados = 0
        cac = 0
        quantidade_clientes = 0
        investimento = 0
        quantidade_cliques = 0
        cpc = 0
        pm = 0
        ctr = '-'
    return render_template(
        'dashboard.html',
        contas=contas_data,
        campanhas=campanhas,
        dados=metricas,
        start_date=start_date,
        end_date=end_date,
        saldo_disponivel=saldo_disponivel,
        alerta_saldo=alerta_saldo,
        saude_score=saude_score,
        is_cassino=is_cassino,
        sugestoes=sugestoes,
        positivos=positivos
    )

@app.route('/api/list-sheets')
def list_sheets():
    creds = get_google_creds()
    gc = gspread.authorize(creds)
    planilhas = [
        {'id': '1w7VPPYppc-RcK_aEAIZO4103KWGM7H2FWj4V_onUIE4', 'nome': 'Planilha 1'},
        {'id': '10tUstU0pmQ5efF5B6hQStsj5MNHlwVuFzFRwFnis9LA', 'nome': 'Planilha 2'},
        {'id': '1XSr6K7eiNNJGU8bapV2w5Dlpb_I5Xw0DwGu6AshLmxA', 'nome': 'Rs Motors'}
    ]
    return jsonify(planilhas)

@app.route('/api/sheets-metrics')
def sheets_metrics():
    creds = get_google_creds()
    gc = gspread.authorize(creds)
    sheet_id = request.args.get('sheet_id', '1w7VPPYppc-RcK_aEAIZO4103KWGM7H2FWj4V_onUIE4')
    aba = request.args.get('aba')
    abas_flag = request.args.get('abas')
    spreadsheet = gc.open_by_key(sheet_id)
    if abas_flag:
        # Retorna lista de abas
        return jsonify({'abas': [ws.title for ws in spreadsheet.worksheets()]})
    worksheet = spreadsheet.worksheet(aba) if aba else spreadsheet.sheet1
    df = get_as_dataframe(worksheet, evaluate_formulas=True, header=0)
    df.columns = [str(col).strip().lower() for col in df.columns]
    def get_num(possiveis):
        for nome in possiveis:
            for col in df.columns:
                if nome in col:
                    try:
                        return pd.to_numeric(df[col], errors='coerce').sum()
                    except Exception:
                        continue
        return 0
    alcance = get_num(['alcance'])
    impressoes = get_num(['impressões', 'impreções'])
    cpl = get_num(['custo por lead', 'cpr', 'custo por resultado'])
    gasto = get_num(['total gasto', 'valor gasto'])
    conversao = get_num(['resultados', 'ações no site', 'novos contatos'])
    receita = get_num(['receita'])
    roi = ((receita - gasto) / gasto) if gasto and receita else None
    return jsonify({
        'Alcance': int(alcance),
        'Impressões': int(impressoes),
        'Custo por Lead': round(float(cpl), 2),
        'Total Gasto': round(float(gasto), 2),
        'Conversão': int(conversao),
        'ROI': round(roi, 2) if roi is not None else '-'
    })

@app.route('/api/export-sheet')
def export_sheet():
    creds = get_google_creds()
    gc = gspread.authorize(creds)
    locale.setlocale(locale.LC_ALL, 'pt_BR.UTF-8')
    sheet_id = request.args.get('sheet_id')
    spreadsheet = gc.open_by_key(sheet_id)
    worksheet = spreadsheet.sheet1
    df = get_as_dataframe(worksheet, evaluate_formulas=True, header=0)
    df.columns = [str(col).strip().lower() for col in df.columns]
    def get_num(possiveis):
        for nome in possiveis:
            for col in df.columns:
                if nome in col:
                    try:
                        return pd.to_numeric(df[col], errors='coerce').sum()
                    except Exception:
                        continue
        return 0
    alcance = get_num(['alcance'])
    impressoes = get_num(['impressões', 'impreções'])
    cpl = get_num(['custo por lead', 'cpr', 'custo por resultado'])
    gasto = get_num(['total gasto', 'valor gasto'])
    conversao = get_num(['resultados', 'ações no site', 'novos contatos'])
    receita = get_num(['receita'])
    roi = ((receita - gasto) / gasto) if gasto and receita else None
    def fmt(n, dec=0):
        try:
            if dec == 0:
                return f"{int(n):,}".replace(",", ".")
            else:
                return f"{float(n):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        except:
            return "-"
    # Lógica de sugestões igual ao dashboard
    sugestoes = []
    positivos = []
    if cpl <= 3:
        positivos.append('Excelente custo por lead.')
    elif cpl > 5:
        sugestoes.append('O custo por lead está elevado, tente otimizar seus anúncios.')
    else:
        sugestoes.append('O custo por lead está dentro da média, mas pode ser melhorado.')
    if alcance > 50000:
        positivos.append('Ótimo alcance, sua campanha está atingindo muitas pessoas.')
    elif alcance < 10000:
        sugestoes.append('O alcance está baixo, tente ampliar o público.')
    if conversao < 10:
        sugestoes.append('A conversão está baixa, avalie o criativo e o público.')
    elif conversao > 100:
        positivos.append('Ótima taxa de conversão.')
    if roi is not None and roi < 0:
        sugestoes.append('Atenção: o ROI está negativo, reveja o investimento.')
    elif roi is not None and roi > 0.2:
        positivos.append('Ótimo retorno sobre investimento (ROI).')
    if gasto > 10000:
        sugestoes.append('O investimento está alto, monitore o retorno.')
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 18)
    pdf.cell(0, 15, 'Relatório de Desempenho', 0, 1, 'C')
    pdf.set_font('Arial', '', 12)
    pdf.ln(5)
    pdf.set_fill_color(255, 215, 0)
    pdf.set_text_color(24, 24, 24)
    pdf.cell(60, 10, 'Métrica', 1, 0, 'C', True)
    pdf.cell(60, 10, 'Valor', 1, 1, 'C', True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255,255,255)
    linhas = [
        ('Alcance', fmt(alcance)),
        ('Impressões', fmt(impressoes)),
        ('Custo por Lead', fmt(cpl, 2)),
        ('Total Gasto', fmt(gasto, 2)),
        ('Conversão', fmt(conversao)),
        ('ROI', f"{round(roi*100,2):,.2f}%".replace(",", "X").replace(".", ",").replace("X", ".") if roi is not None else '-')
    ]
    for met, val in linhas:
        pdf.cell(60, 10, met, 1, 0, 'C')
        pdf.cell(60, 10, str(val), 1, 1, 'C')
    pdf.ln(8)
    pdf.set_font('Arial', 'B', 13)
    pdf.cell(0, 10, 'Análise e Sugestões', 0, 1, 'L')
    pdf.set_font('Arial', '', 11)
    if positivos:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 8, 'Pontos positivos:', 0, 1, 'L')
        for p in positivos:
            pdf.cell(0, 7, f'- {p}', 0, 1, 'L')
    if sugestoes:
        pdf.set_text_color(200, 120, 0)
        pdf.cell(0, 8, 'Oportunidades:', 0, 1, 'L')
        for s in sugestoes:
            pdf.cell(0, 7, f'- {s}', 0, 1, 'L')
    pdf.set_text_color(120,120,120)
    pdf.ln(6)
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 10, 'Relatório gerado automaticamente pelo Dashboard IA Midas', 0, 1, 'C')
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    output = io.BytesIO(pdf_bytes)
    output.seek(0)
    return send_file(
        output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='relatorio_customizado.pdf'
    )

# Exportação de relatório customizado em PDF
@app.route('/export-report')
@login_required
def export_report():
    resultados = 0  # valor padrão para evitar NameError
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    conta_id = request.args.get('conta_id')
    campanha_id = request.args.get('campanha_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    nome_campanha = request.args.get('nome_campanha', '')
    # Buscar nome da conta para identificar se é cassino
    contas_resp = requests.get(
        'https://graph.facebook.com/v19.0/me/adaccounts',
        params={'access_token': meta.access_token, 'fields': 'id,name'}
    )
    contas_data = contas_resp.json().get('data', [])
    contas_cassino = [
        'jhon', 'brasil boloes', 'roleta vip', 'conta lucas', 'brazzo bet', 'top cash', 'el salvador', 'bm el salvador'
    ]
    contas_normais = [
        'rs motos', 'agulha magica', 'karine', 'casal do milhao', 'fabio', 'atmo'
    ]
    nome_conta = None
    for c in contas_data:
        if c['id'] == conta_id:
            nome_conta = c.get('name', '').strip().lower()
            break
    is_cassino = False
    nome_conta_normalizado = normalizar_nome(nome_conta)
    for nome in contas_cassino:
        if normalizar_nome(nome) in nome_conta_normalizado:
            is_cassino = True
            break
    # Buscar métricas da campanha (igual dashboard)
    print('DEBUG PDF - Parâmetros:', {'conta_id': conta_id, 'campanha_id': campanha_id, 'start_date': start_date, 'end_date': end_date})
    url = f'https://graph.facebook.com/v19.0/{campanha_id}/insights'
    params = {
        'access_token': meta.access_token,
        'fields': 'impressions,reach,clicks,spend,actions,cost_per_action_type',
    }
    if start_date and end_date:
        params['time_range'] = f'{{"since":"{start_date}","until":"{end_date}"}}'
    else:
        params['date_preset'] = 'last_30d'
    response = requests.get(url, params=params)
    data = response.json()
    print('DEBUG PDF - Dados retornados:', data)
    insights_list = data.get('data', [])
    insights = insights_list[0] if insights_list else {}
    impressoes = int(insights.get('impressions', 0) or 0)
    alcance = int(insights.get('reach', 0) or 0)
    cliques = int(insights.get('clicks', 0) or 0)
    gasto = float(insights.get('spend', 0) or 0)
    cpl = 0  # Inicializa cpl para evitar UnboundLocalError nas sugestões
    cpc = 0  # Inicializa cpc também, se necessário
    conversoes = 0  # Inicializa conversoes também, se necessário
    ctr = f"{(cliques/impressoes*100):.2f}%" if impressoes else '-' 
    # Buscar clientes (FTD ou lead) para o PDF
    if 'actions' in insights:
        for a in insights['actions']:
            if is_cassino:
                if a['action_type'] == 'offsite_conversion.fb_pixel_purchase':
                    conversoes += int(a['value'])
            else:
                if a['action_type'] in [
                    'link_click',
                    'onsite_conversion.messaging_conversation_started_7d',
                    'onsite_conversion.messaging_first_reply',
                    'onsite_conversion.pre_add_to_cart',
                    'onsite_conversion.initiated_checkout',
                    'onsite_conversion.add_to_cart',
                    'onsite_conversion.purchase',
                    'offsite_conversion.fb_pixel_purchase',
                    'lead',
                    'offsite_conversion.lead',
                    'contact',
                    'onsite_conversion.lead_grouped',
                    'onsite_conversion.submit_application',
                    'onsite_conversion.schedule',
                    'onsite_conversion.add_payment_info',
                    'onsite_conversion.start_trial',
                    'onsite_conversion.subscribe',
                    'onsite_conversion.complete_registration',
                    'onsite_conversion.search',
                    'onsite_conversion.view_content'
                ]:
                    conversoes += int(a['value'])
    if conversoes > 0:
        cpl = gasto / conversoes
    if cliques > 0:
        cpc = gasto / cliques
    # Gerar sugestões reais (igual dashboard)
    sugestoes = []
    positivos = []
    if cpl and cpl <= 3:
        positivos.append('Excelente custo por lead.')
    elif cpl and cpl > 5:
        sugestoes.append('O custo por lead está elevado, tente otimizar seus anúncios.')
    elif cpl:
        sugestoes.append('O custo por lead está dentro da média, mas pode ser melhorado.')
    if alcance and alcance > 50000:
        positivos.append('Ótimo alcance, sua campanha está atingindo muitas pessoas.')
    elif alcance and alcance < 10000:
        sugestoes.append('O alcance está baixo, tente ampliar o público.')
    if conversoes and conversoes < 10:
        sugestoes.append('A conversão está baixa, avalie o criativo e o público.')
    elif conversoes and conversoes > 100:
        positivos.append('Ótima taxa de conversão.')
    if ctr and ctr != '-' and float(ctr.replace('%','')) < 1.0:
        sugestoes.append('CTR baixo, teste novos criativos e públicos.')
    elif ctr and ctr != '-' and float(ctr.replace('%','')) > 3.0:
        positivos.append('Ótimo CTR!')
    proximos_passos = sugestoes if sugestoes else ['Continue monitorando a campanha.']
    # Calcular saúde da campanha (igual dashboard)
    score = 0
    if cpl and cpl <= 3:
        score += 30
    elif cpl and cpl <= 5:
        score += 20
    elif cpl:
        score += 5
    if conversoes and conversoes > 100:
        score += 20
    elif conversoes and conversoes >= 10:
        score += 10
    if alcance and alcance > 50000:
        score += 15
    elif alcance and alcance >= 10000:
        score += 10
    try:
        ctr_val = float(ctr.replace('%','')) if ctr and ctr != '-' else 0
    except:
        ctr_val = 0
    if ctr_val > 3:
        score += 15
    elif ctr_val >= 1:
        score += 10
    # Buscar saldo disponível da conta
    saldo_disponivel = None
    if conta_id:
        conta_info_resp = requests.get(
            f'https://graph.facebook.com/v19.0/{conta_id}',
            params={'access_token': meta.access_token, 'fields': 'balance'}
        )
        conta_info = conta_info_resp.json()
        saldo_disponivel = conta_info.get('balance')
    saldo_float = float(saldo_disponivel)/100 if saldo_disponivel else 0
    if saldo_float > 100:
        score += 10
    elif saldo_float >= 30:
        score += 5
    saude_score = min(int(score * 100 / 90), 100)
    saude_label = 'Ótimo' if saude_score >= 80 else ('Bom' if saude_score >= 50 else 'Ruim')
    saude_cor = (0,230,118) if saude_score >= 80 else ((255,214,0) if saude_score >= 50 else (255,23,68))
    # Garantir que as métricas tenham valores válidos
    if not insights or (impressoes == 0 and alcance == 0 and cliques == 0 and gasto == 0 and conversoes == 0):
        # Sem dados para o período
        impressoes = 0
        alcance = 0
        cliques = 0
        gasto = 0
        conversoes = 0
        cpl = 0
        cpc = 0
        ctr = '-'
        sugestoes = []
        positivos = []
        mensagem_sem_dados = True
    else:
        mensagem_sem_dados = False
    # Cálculo das novas métricas (iguais ao dashboard)
    investimento = gasto
    quantidade_cliques = cliques
    cpc = (gasto / cliques) if cliques else 0
    pm = alcance  # PM = Pessoas Alcançadas
    ctr_valor = (cliques / impressoes * 100) if impressoes else 0
    ctr = f"{ctr_valor:.2f}%" if impressoes else '-'
    quantidade_clientes = conversoes
    cac = (gasto / quantidade_clientes) if quantidade_clientes else 0
    # Sugestões e pontos positivos (análise preditiva baseada nas métricas)
    sugestoes = []
    positivos = []
    # CAC/CPL
    if cac and cac <= 5:
        positivos.append('Excelente CAC/CPL. Continue otimizando para manter esse resultado.')
    elif cac and cac > 15:
        sugestoes.append('O CAC/CPL está alto. Considere revisar segmentação, criativos e oferta. Teste públicos diferentes e otimize anúncios de baixo desempenho.')
    elif cac:
        sugestoes.append('O CAC/CPL está dentro da média, mas pode ser melhorado. Experimente pequenas mudanças em criativos ou segmentação.')
    # Clientes/Leads
    if quantidade_clientes and quantidade_clientes > 50:
        positivos.append('Ótima quantidade de clientes/leads para o período!')
    elif quantidade_clientes and quantidade_clientes < 5:
        sugestoes.append('Poucos clientes/leads convertidos. Analise o funil de cadastro, revise a oferta e teste abordagens diferentes para aumentar conversão.')
    # CTR
    if ctr and ctr != '-' and float(ctr.replace('%','')) < 1.0:
        sugestoes.append('CTR baixo. Teste banners e criativos mais chamativos, ajuste chamadas para ação e avalie se o público está bem segmentado.')
    elif ctr and ctr != '-' and float(ctr.replace('%','')) > 5.0:
        positivos.append('CTR excelente! Seus anúncios estão atraentes para o público.')
    elif ctr and ctr != '-' and float(ctr.replace('%','')) < 2.0:
        sugestoes.append('CTR abaixo do ideal. Considere testar novos formatos de anúncio e revisar o texto das campanhas.')
    # Investimento x Conversão
    if investimento > 1000 and quantidade_clientes < 10:
        sugestoes.append('Investimento alto e poucos clientes. Avalie o ROI, reduza orçamento em campanhas pouco performáticas e foque nos melhores anúncios.')
    elif investimento < 200 and quantidade_clientes > 20:
        positivos.append('Ótima eficiência: muitos clientes com baixo investimento!')
    # Impressões e Alcance (para contas normais)
    if not is_cassino:
        if impressoes < 10000:
            sugestoes.append('Poucas impressões. Amplie o orçamento ou aumente o público para gerar mais visibilidade.')
        if pm < 5000:
            sugestoes.append('Alcance baixo. Tente expandir a segmentação ou aumentar o investimento.')
        if impressoes > 100000 and quantidade_clientes < 10:
            sugestoes.append('Muitas impressões, mas poucas conversões. Reveja a oferta, criativos e segmentação.')
    # PM (para cassinos)
    if is_cassino:
        if pm < 5000:
            sugestoes.append('Poucas pessoas alcançadas. Considere aumentar o orçamento ou expandir o público.')
        if pm > 50000 and quantidade_clientes < 10:
            sugestoes.append('Muitas pessoas alcançadas, mas poucas conversões. Teste novas ofertas ou revise o funil de cadastro.')
    # CPC
    if cpc and cpc > 3:
        sugestoes.append('CPC alto. Tente melhorar a relevância dos anúncios e a segmentação.')
    elif cpc and cpc < 0.5:
        positivos.append('CPC muito baixo! Excelente eficiência nos cliques.')
    # Sempre incluir pelo menos uma sugestão construtiva
    if not sugestoes:
        sugestoes.append('Continue testando novos criativos, públicos e ofertas para manter ou melhorar a performance, mesmo com resultados excelentes.')
    # PDF estilizado com todas as métricas e sugestões
    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(30,30,30)
    pdf.rect(0,0,210,297,'F')
    pdf.set_font('Arial', 'B', 22)
    pdf.set_text_color(255,215,0)
    pdf.cell(0, 18, f'Relatório - {limpar_texto_pdf(nome_campanha)}', 0, 1, 'C')
    pdf.set_font('Arial', '', 13)
    pdf.set_text_color(200,200,200)
    periodo = f'Período: {start_date} a {end_date}' if start_date and end_date else ''
    pdf.cell(0, 10, periodo, 0, 1, 'C')
    pdf.ln(6)
    if mensagem_sem_dados:
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(255, 80, 80)
        pdf.cell(0, 16, 'Nenhum dado encontrado para o período selecionado.', 0, 1, 'C')
        pdf.set_text_color(255,255,255)
        pdf.ln(10)
    # Bloco de métricas atualizado (igual aos cards do dashboard)
    pdf.set_font('Arial', 'B', 15)
    pdf.set_text_color(255,215,0)
    pdf.cell(0, 12, 'Métricas Gerais', 0, 1, 'L')
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(255,255,255)
    if is_cassino:
        pdf.cell(60, 10, 'PM (Pessoas Alcançadas)', 1, 0, 'C')
        pdf.cell(60, 10, f'{pm:,}'.replace(",","."), 1, 1, 'C')
    else:
        pdf.cell(60, 10, 'Impressões', 1, 0, 'C')
        pdf.cell(60, 10, f'{impressoes:,}'.replace(",","."), 1, 1, 'C')
        pdf.cell(60, 10, 'Alcance', 1, 0, 'C')
        pdf.cell(60, 10, f'{pm:,}'.replace(",","."), 1, 1, 'C')
    pdf.cell(60, 10, 'CTR', 1, 0, 'C')
    pdf.cell(60, 10, ctr, 1, 1, 'C')
    pdf.cell(60, 10, '{0}'.format('CAC' if is_cassino else 'CPL'), 1, 0, 'C')
    pdf.cell(60, 10, f'R$ {cac:.2f}' if cac else '-', 1, 1, 'C')
    pdf.cell(60, 10, '{0}'.format('Clientes (Depósito/FTD)' if is_cassino else 'Leads'), 1, 0, 'C')
    pdf.cell(60, 10, f'{quantidade_clientes}', 1, 1, 'C')
    pdf.cell(60, 10, 'Investimento', 1, 0, 'C')
    pdf.cell(60, 10, f'R$ {investimento:.2f}', 1, 1, 'C')
    pdf.cell(60, 10, 'Cliques', 1, 0, 'C')
    pdf.cell(60, 10, f'{quantidade_cliques}', 1, 1, 'C')
    pdf.cell(60, 10, 'CPC', 1, 0, 'C')
    pdf.cell(60, 10, f'R$ {cpc:.2f}' if cpc else '-', 1, 1, 'C')
    pdf.ln(8)
    # Sugestões
    if sugestoes:
        pdf.set_font('Arial', 'B', 13)
        pdf.set_text_color(255,215,0)
        pdf.cell(0, 10, 'Sugestões e Oportunidades', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        pdf.set_text_color(255,255,255)
        for s in sugestoes:
            pdf.multi_cell(0, 8, f'- {s}')
        pdf.ln(6)
    # Pontos positivos
    if positivos:
        pdf.set_font('Arial', 'B', 13)
        pdf.set_text_color(0,230,118)
        pdf.cell(0, 10, 'Pontos Positivos', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        pdf.set_text_color(255,255,255)
        for p in positivos:
            pdf.multi_cell(0, 8, f'- {p}')
        pdf.ln(6)
    # Se não houver pontos positivos, não mostra nada desse bloco
    # Criativos (exemplo)
    pdf.set_font('Arial', 'B', 13)
    pdf.set_text_color(255,215,0)
    pdf.cell(0, 10, 'Criativos Utilizados', 0, 1, 'L')
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(255,255,255)
    criativos = ['WhatsApp Video 2023-05-09.mp4']
    for c in criativos:
        pdf.cell(0, 8, f'- {c}', 0, 1, 'L')
    pdf.ln(6)
    pdf.set_text_color(120,120,120)
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 10, 'Relatório gerado automaticamente pelo Dashboard IA Midas', 0, 1, 'C')
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    output = io.BytesIO(pdf_bytes)
    output.seek(0)
    # Definir nome do arquivo com base no nome da conta (capitalizado e limpo)
    nome_arquivo = None
    for c in contas_data:
        if c['id'] == conta_id:
            nome_arquivo = c.get('name', '').strip()
            break
    if not nome_arquivo:
        nome_arquivo = 'relatorio_meta_ads'
    nome_arquivo = nome_arquivo.title()
    caracteres_invalidos = ' /\\.,;:?"\'|<>*@$#%&()[]{}=+`~^\n\r\t'
    for ch in caracteres_invalidos:
        nome_arquivo = nome_arquivo.replace(ch, '_')
    nome_arquivo = '_'.join(filter(None, nome_arquivo.split('_')))
    nome_arquivo = nome_arquivo[:40]  # Limita tamanho
    nome_arquivo += '.pdf'
    return send_file(
        output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=nome_arquivo
    )

@app.route('/otimizar-campanha', methods=['POST'])
@login_required
def otimizar_campanha():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    campanha_id = request.form.get('campanha_id')
    cpl = float(request.form.get('cpl', 0))
    saldo = float(request.form.get('saldo', 0))
    # Buscar conjunto de anúncios da campanha
    conjuntos_resp = requests.get(
        f'https://graph.facebook.com/v19.0/{campanha_id}/adsets',
        params={'access_token': meta.access_token, 'fields': 'id,daily_budget'}
    )
    conjuntos = conjuntos_resp.json().get('data', [])
    if not conjuntos:
        return jsonify({'success': False, 'message': 'Nenhum conjunto de anúncios encontrado para otimizar.'})
    adset_id = conjuntos[0]['id']
    daily_budget = int(conjuntos[0].get('daily_budget', 0))
    novo_budget = daily_budget
    acao = ''
    if cpl <= 3 and saldo > 50:
        novo_budget = int(daily_budget * 1.1)
        acao = 'aumentado'
    elif cpl > 5:
        novo_budget = int(daily_budget * 0.9)
        acao = 'reduzido'
    else:
        return jsonify({'success': True, 'message': 'Campanha já está otimizada. Nenhuma ação necessária.'})
    # Atualizar orçamento via API
    update_resp = requests.post(
        f'https://graph.facebook.com/v19.0/{adset_id}',
        params={'access_token': meta.access_token},
        data={'daily_budget': novo_budget}
    )
    if update_resp.status_code == 200:
        return jsonify({'success': True, 'message': f'Orçamento {acao} para R$ {novo_budget/100:.2f} com base no CPL.'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao otimizar campanha: ' + update_resp.text})

@app.route('/api/meta-metrics-history')
@login_required
def meta_metrics_history():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    conta_id = request.args.get('conta_id')
    campanha_id = request.args.get('campanha_id')
    # Por padrão, últimos 7 dias
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if not end_date:
        end_date = datetime.now().strftime('%Y-%m-%d')
    if not start_date:
        start_date = (datetime.strptime(end_date, '%Y-%m-%d') - timedelta(days=6)).strftime('%Y-%m-%d')
    url = f'https://graph.facebook.com/v19.0/{campanha_id}/insights'
    params = {
        'access_token': meta.access_token,
        'fields': 'date_start,date_stop,impressions,reach,clicks,spend,actions',
        'time_increment': 1,
        'time_range': json.dumps({'since': start_date, 'until': end_date})
    }
    response = requests.get(url, params=params)
    data = response.json()
    dias = []
    alcance = []
    impressoes = []
    cliques = []
    conversoes = []
    custo = []
    for d in data.get('data', []):
        dias.append(d.get('date_start'))
        alcance.append(int(d.get('reach', 0) or 0))
        impressoes.append(int(d.get('impressions', 0) or 0))
        cliques.append(int(d.get('clicks', 0) or 0))
        custo.append(float(d.get('spend', 0) or 0))
        conv = 0
        for a in d.get('actions', []):
            if a['action_type'] in ['lead', 'offsite_conversion.lead']:
                conv += int(a['value'])
        conversoes.append(conv)
    return jsonify({
        'labels': dias,
        'alcance': alcance,
        'impressoes': impressoes,
        'cliques': cliques,
        'conversoes': conversoes,
        'custo': custo
    })

# Rota para integração com OpenAI GPT
@app.route('/api/midas-chat', methods=['POST'])
def midas_chat():
    data = request.get_json()
    mensagem = data.get('mensagem', '')
    if not mensagem:
        return jsonify({'resposta': 'Não recebi nenhuma mensagem.'})
    # Resposta simulada do Midas (sem OpenAI)
    resposta_padrao = (
        "Olá! Sou o Midas, seu assistente de marketing digital e apostas. No momento, a integração com IA está temporariamente desativada. "
        "Posso te ajudar com explicações sobre métricas, dicas de otimização, sugestões para campanhas, checklist de boas práticas, ou motivação! "
        "Pergunte sobre CAC, CTR, funil, melhores práticas, ou peça uma frase motivacional. Em breve, a IA estará de volta!"
    )
    return jsonify({'resposta': resposta_padrao})

# Caminho para o arquivo de credenciais
def get_google_creds():
    creds_json = os.environ.get('GOOGLE_CREDS_JSON')
    if not creds_json:
        raise Exception("Credenciais do Google não encontradas no ambiente!")
    info = json.loads(creds_json)
    return Credentials.from_service_account_info(info, scopes=[
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive'
    ])

def limpar_texto_pdf(texto):
    if texto is None:
        return ""
    return (
        texto.replace("—", "-")
             .replace("–", "-")
             .replace(""", '"')
             .replace(""", '"')
             .replace("'", "'")
             .replace("'", "'")
    )

def normalizar_nome(nome):
    if not nome:
        return ''
    nome = nome.lower().strip()
    nome = ''.join(c for c in unicodedata.normalize('NFD', nome) if unicodedata.category(c) != 'Mn')
    nome = nome.replace('-', ' ').replace('_', ' ')
    nome = ' '.join(nome.split())
    return nome

def upload_file_to_storage(file):
    if USE_S3:
        filename = secure_filename(file.filename)
        s3_client.upload_fileobj(
            file,
            S3_BUCKET,
            filename,
            ExtraArgs={"ACL": "public-read"}
        )
        file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
        return file_url
    else:
        # Upload local (antigo)
        filepath = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        filepath = upload_file_to_storage(file)
        return filepath

if __name__ == '__main__':
    app.run(debug=True)

