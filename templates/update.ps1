cd D:\Projetos\suporte-trello 

git init 

# garante que est� na branch main 
git branch -M main 

# adiciona todos os arquivos novos e modificados 
git add . 

# cria um commit 
git commit -m "Atualiza��o" 

# garante que o remoto est� configurado 
git remote remove origin 2>$null git remote add origin https://github.com/guilherme9lucaslider-svg/suporte-trello.git 

# envia para o GitHub na branch main (for�ando a substituir o conte�do antigo) 
git push -u origin main --force 

exit