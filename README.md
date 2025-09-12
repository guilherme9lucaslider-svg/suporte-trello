Suporte Trello — Guia Rápido

Requisitos
- Python 3.10+
- PostgreSQL

Configuração
1. Crie um arquivo .env na raiz com:

ADMIN_USER=...
ADMIN_PASS=...
APP_SECRET=chave-secreta-aleatoria
DATABASE_URL=postgresql://usuario:senha@host:5432/suporte_trello
# ou defina DB_* (usados somente se DATABASE_URL não existir)
DB_HOST=...
DB_NAME=...
DB_USER=...
DB_PASS=...
DB_PORT=5432
DB_SSLMODE=disable
TRELLO_KEY=...
TRELLO_TOKEN=...
TRELLO_BOARD=...
TRELLO_LIST="Chamados abertos"
TRELLO_LIST_ID=...
HIDE_DOWNLOAD_BUTTON=1
APP_DESKTOP=0

2. Instale dependências:

pip install -r requirements.txt

3. Crie as tabelas (se necessário):

python tools/db_init.py

4. Execute o servidor:

python app.py

Endpoints úteis
- /admin/login: painel administrativo
- /api/diagnostico: status de integração com Trello
- /health: liveness (app está de pé)
- /ready: readiness (DB e Trello OK)

App Desktop (Electron)
Configure PANEL_URL no .env do painel-desktop/ para apontar para o seu servidor.
Rode com:

cd painel-desktop
npm install
npm start


