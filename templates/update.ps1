Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location -Path 'D:\Projetos\suporte-trello'

Write-Host "Iniciando processo de deploy..." -ForegroundColor Cyan

# Configuracoes Git
git config --local core.autocrlf true
git config --local core.safecrlf false
git config --local advice.addIgnoredFile false
git config --local push.default simple

# Inicializa repositorio se necessario
if (-not (Test-Path '.git')) {
  Write-Host "Inicializando repositorio Git..." -ForegroundColor Green
  git init | Out-Null
}

# Garante branch main
git branch -M main 2>$null | Out-Null

# Adiciona arquivos
Write-Host "Adicionando arquivos..." -ForegroundColor Yellow
git add -A 2>$null

# Verifica mudancas
$status = git status --porcelain
if ($status) {
    Write-Host "Criando commit..." -ForegroundColor Green
    $msg = "Atualizacao $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    git commit -m $msg 2>$null
    Write-Host "Commit criado: $msg" -ForegroundColor Green
} else {
    Write-Host "Nenhuma mudanca detectada." -ForegroundColor Blue
}

# Configura remoto
Write-Host "Configurando repositorio remoto..." -ForegroundColor Yellow
try { git remote remove origin 2>$null | Out-Null } catch {}
git remote add origin 'https://github.com/guilherme9lucaslider-svg/suporte-trello.git' 2>$null

# Push
Write-Host "Enviando para GitHub..." -ForegroundColor Yellow
git push -u origin main --force 2>$null

Write-Host "Deploy concluido com sucesso!" -ForegroundColor Green

exit 0