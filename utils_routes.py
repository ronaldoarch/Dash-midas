from datetime import datetime

# Armazenamento em memória — para persistência real, use JSON ou banco
client_tokens = {}

def get_dates_from_request(request):
    start_date = request.args.get("start_date", "2024-01-01")
    end_date = request.args.get("end_date", "2024-12-31")

    try:
        datetime.strptime(start_date, "%Y-%m-%d")
        datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Datas devem estar no formato YYYY-MM-DD.")

    return start_date, end_date

def _get_data_for_gemini(client_name):
    """
    Retorna os dados do cliente, incluindo token atualizado.
    """
    return {
        "name": client_name,
        "id": 123,
        "industry": "E-commerce",
        "access_token": client_tokens.get(client_name, "TOKEN_PADRAO")  # <- pega token salvo
    }

def update_token(client_name, new_token):
    """
    Atualiza o token de acesso do cliente.
    """
    client_tokens[client_name] = new_token
