Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location -Path 'D:\Projetos\suporte-trello'

# Inicializa repositório se necessário
if (-not (Test-Path '.git')) {
  git init | Out-Null
}

# Garante branch main
git branch -M main | Out-Null

# Adiciona arquivos
git add -A

# Cria commit (mensagem sem acentos para evitar problemas de encoding)
$msg = "Atualizacao $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
git commit -m $msg

# Configura remoto de forma idempotente
try { git remote remove origin | Out-Null } catch {}
git remote add origin 'https://github.com/guilherme9lucaslider-svg/suporte-trello.git'

# Push forçado (cuidado: sobrescreve remoto)
git push -u origin main --force

exit 0