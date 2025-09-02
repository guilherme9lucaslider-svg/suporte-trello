cd D:\Projetos\suporte-trello 

git init 

# garante que está na branch main 
git branch -M main 

# adiciona todos os arquivos novos e modificados 
git add . 

# cria um commit 
git commit -m "Atualização" 

# garante que o remoto está configurado 
git remote remove origin 2>$null git remote add origin https://github.com/guilherme9lucaslider-svg/suporte-trello.git 

# envia para o GitHub na branch main (forçando a substituir o conteúdo antigo) 
git push -u origin main --force 

exit