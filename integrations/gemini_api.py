# integrations/gemini_api.py

def generate_goal_original(client_data, start_date, end_date):
    return f"Meta analisada para {client_data['name']} de {start_date} a {end_date}"

def generate_creative_risk(client_data, start_date, end_date):
    return f"Sugestões criativas geradas para {client_data['name']}"

def generate_budget_recommendations(client_data, start_date, end_date):
    return f"Recomendações de orçamento para {client_data['name']}"

def generate_risk(client_data, start_date, end_date):
    return f"Análise de risco para {client_data['name']}"
def _get_data_for_gemini(client_id):
    try:
        with open(f"tokens/{client_id}.txt", "r") as f:
            access_token = f.read().strip()
        return {
            "client_id": client_id,
            "access_token": access_token
        }
    except FileNotFoundError:
        raise Exception(f"Token para o cliente '{client_id}' não encontrado.")
