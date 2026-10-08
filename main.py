
from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'Aqui_e_a_chave_da_turma_a'

#CONEXÃO COM O BANCO
host = 'localhost'
database = r'C:\Users\Aluno\Desktop\jamily\BANCO.FDB'
user = 'SYSDBA'
password = 'sysdba'

con = fdb.connect(host=host, database=database, user=user, password=password)

@app.route('/') #ROTA INCIAL - LANDING PAGE
def index():
    return render_template('index.html')

#ROTA QUE DIRECIONA PARA A PÁGINA CADASTRO DE USUÁRIO
@app.route('/cadastro_usu')
def cadastro_usu():
    return render_template('cadastro_usuario.html')

# VERIFICAR SENHA FORTE
def senha_forte(senha):
    if len(senha) < 8: #senha menor que 8 digitos
        return False
    if senha.islower(): #letra minuscula
        return False
    if senha.isalpha(): # caracter especial
        return False
    if senha.isdigit(): # digitos
        return False
    else:
        return True

@app.route('/cadastrar', methods=['POST']) #ROTA QUE REALIZA O CADASTRO
def cadastrar():
    nome = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']
    mao_obra = request.form['mao_obra']

    if not mao_obra:   #SE A MÃO DE OBRA NÃO TIVER SIDO INFORMADA
        flash("Mão de obra não informada!")
        return redirect(url_for('cadastro_usu'))

    mao_obra = float(mao_obra) #CONVERSÃO DE STRING PARA NÚMERO

    #SE A SENHA INSERIDA NÃO ATINGIR TODOS OS REQUISITOS PARA SENHA FORTE
    if not senha_forte(senha):
        flash("Senha fraca! Precisa conter 8 ou mais caracteres, pelo menos uma letra maiúscula, um número e um caracter especial")
        return redirect(url_for('cadastro_usu'))

    cursor = con.cursor() #ABRINDO O CURSOR

    try:  #TRATAMENTO DE ERRO

        #SELECIONA O USUARIO QUE POSSUI ESTE EMAIL
        cursor.execute("""SELECT 1
                          FROM usuario u
                          WHERE email = ?""", (email,))

        # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
        confere_email = cursor.fetchone()

        if confere_email:  #SE JA TIVER ESTE EMAIL CADASTRADO
            flash('Erro: Email já cadastrado')
            return redirect(url_for('cadastro_usu'))

        # GERA CRIPITOGRAFIA DE SENHA
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        #EXECUÇÃO DO INSERT - CADASTRO DO USUÁRIO
        cursor.execute(""" INSERT INTO usuario (nome, email, senha, mao_obra, tentativas)
                           VALUES (?, ?, ?, ?, ?)""", (nome, email, senha_hash,mao_obra, 0))

        con.commit() #SALVA AS INFORMAÇÕES
        flash("Usuário cadastrado com sucesso")
        return redirect(url_for('login_usu'))


    except Exception as e: #SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback() #CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('cadastro_usu'))

    finally:
        cursor.close() #FECHA A CONVERSA COM O BANCO


#ROTA QUE REALIZA O LOGIN DE USUÁRIO
@app.route('/login_usu', methods=['GET', 'POST'])
def login_usu():
    if request.method == 'GET': #SE A PÁGINA DE LOGIN FOI ACESSADA
        return render_template('login_usuario.html')

    email = request.form['email']
    senha = request.form['senha']

    cursor = con.cursor() #ABRINDO O CURSOR
    try:
        # SELECIONA OS DADOS QUE PERTENCEM AO EMAIL INSERIDO
        cursor.execute("""SELECT id_usuario,nome, senha, tentativas
        FROM usuario u
        WHERE u.email = ? """, (email,))

        # CONFERFE SE JÁ TEM ESTE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        if not usuario: #SE NÃO TIVER ESTE USUÁRIO CADASTRADO
            flash("Usuário não encontrado")
            return redirect(url_for('login_usu'))

        # ARMAZENAMENTO DOS CAMPOS DE LOGIN NA VARIAVEL
        id_usuario,nome, senha_hash, tentativas = usuario

        #SE A QUANTIDADE TENTATIVAS DE LOGIN FOR MAIOR OU IGUAL A 3
        if tentativas >= 3:
            flash("Você passou de 3 tentativas! Sua conta foi bloqueada.")
            return redirect(url_for('login_usu'))


        if usuario: #SE ESTIVER ESTE USUÁRIO CADADTRADO
            if bcrypt.check_password_hash(senha_hash, senha): # VERIFICA SE A SENHA INSERIDA É IGUAL A QUE FOI CADASTRADA

                #ATUALIZA O NUMERO DE TENTATIVAS PARA ZERO, APOS ACERTAR A SENHA DE USUÁRIO
                cursor.execute("""UPDATE usuario
                set tentativas = 0
                where id_usuario = ?""", (id_usuario,))

                con.commit()#SALVA AS INFORMAÇÕES

                session['id_usuario'] = id_usuario #GUARDA O ID DOS USUÁRIOS LOGADOS
                session['usuario_nome'] = nome  #GUARDA O NOME DOS USUÁRIOS LOGADOS

                flash('Conta logada')
                return redirect(url_for('home'))

            else:

                # ATUALIZA O NÚMERO DE TENTATIVAS (de um em um) A CADA VEZ QUE ERRAR A SENHA DE CADASTRO
                cursor.execute("""UPDATE usuario
                set tentativas = tentativas + 1  
                where id_usuario = ?""", (id_usuario,))

                con.commit() #SALVA AS INFORMAÇÕES

                # SE O NÚMERO DE TENTATIVAS FOI MAIOR OU IGUAL A 3
                if tentativas + 1 >= 3:
                    flash('Você passou de 3 tentativas! Sua conta foi bloqueada.')
                else: #SE AS TENTATIVAS MÁXIMAS AINDA NÃO FOREM ATINGIDAS
                    flash('Email ou senha inválida')
                return redirect(url_for('login_usu'))
        return render_template('login_usu.html')

    except Exception as e: #SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback() #CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('login_usu'))
    finally:
        cursor.close() #FECHA A CONVERSA COM O BANCO


@app.route('/perfil') #ROTA DA PAGINA DE PERFIL DO USUARIO
def perfil():

    if 'id_usuario' not in session: #SENÃO TIVER O ID DE USUÁRIO NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(url_for('login_usu'))

    cursor = con.cursor() #ABRINDO O CURSOR
    try:
        # SELECONA OS DADOS QUE PERTENCE AO USUÁRIO LOGADO
        cursor.execute("""SELECT id_usuario,nome, email, senha, mao_obra
        FROM usuario u
        WHERE id_usuario = ? """, (session['id_usuario'],))

        # CONFERFE SE JÁ TEM ESTE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        #SE ESTE USUÁRIO NÃO EXISTIR
        if not usuario:
            flash('Usuário não encontrado')
            return redirect(url_for('home'))

        #ARMAZENAMENTO DOS CAMPOS - DADOS NA VARIAVEL
        id_usuario,nome, email, senha_hash, mao_obra = usuario

        #RETORNA NA PÁGINA DE PERFIL, AS INFORMAÇÕES CADASTRADAS DO USUÁRIO LOGADO
        return render_template('perfil.html',usuario=usuario,
            nome=nome,
            email=email,
            senha=senha_hash,
            mao_obra=mao_obra,

        )

    except Exception as e: #SE ACONTECER ALGUM ERRO
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close() #FECHA A CONVERSA COM O BANCO


#ROTA QUE DIRECIONA PARA A PÁGINA EDITAR PERFIL
@app.route('/editar_perfil/<int:id>', methods=['GET','POST'])
def editar_perfil(id):
    cursor = con.cursor()
    try:
        #SELECIONA OS DADOS QUE PERTENCEM AQUELE ID DE USUÁRIO
        cursor.execute("""SELECT id_usuario, nome, email, senha, mao_obra
                          from usuario WHERE ID_usuario = ?""", (id,))

        #CONFERFE SE JÁ TEM ESTE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()


        if not usuario: #SE ESTE USUÁRIO NÃO EXISTIR
            flash('Usuário não encontrado')
            return redirect(url_for('index'))

        #ARMAZENAMENTO DOS CAMPOS NA VARIAVEL
        id_usuario, nome, email, senha_atual, mao_obra = usuario

        #ENVIO DOS DADOS INSERIDOS
        if request.method == 'POST':
            nome = request.form['nome']
            email = request.form['email']
            nova_senha = request.form['senha']
            mao_obra = request.form['mao_obra']

            # SELECIONA AS SENHAS ANTIGAS DO USUÁRIO (da mais recente pra mais antiga)
            cursor.execute("""SELECT senha
                           FROM senhas_utilizadas
                           WHERE id_usuario = ?
                           ORDER BY id_usuario DESC
                           """, (id_usuario,))

            #CONFERE E PEGA TODAS AS SENHAS QUE PERTENCEM AO USUÁRIO
            senhas_antigas = cursor.fetchall()

            # VERIFICAÇÃO DAS 3 ÚLTIMAS SENHAS
            contador = 0 #CONTROLE DE QUANTAS SENHAS FORAM VERIFICADAS

            #ANALISA UMA SENHA ANTIGA POR VEZ, ENTRE TODAS AS VERIFICADAS
            for senha_antiga in senhas_antigas:

                if contador == 3: #SE VERIFICAR 3 SENHAS
                    break

                    # VERIFICA SE A NOVA SENHA É IGUAL A QUE FOI CADASTRADA
                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):
                    flash('Você não pode usar uma das últimas 3 senhas.')
                    return redirect(url_for('editar_perfil', id=id_usuario))

                contador += 1 #VERIFICAÇÕES DE SENHA (uma por vez)

            # VERIFICAÇÃO DA SENHA ATUAL
            if bcrypt.check_password_hash(senha_atual, nova_senha): #SE A NOVA SENHA É IGUAL A SENHA ATUAL
                flash('Você não pode usar a senha atual.')
                return redirect(url_for('editar_perfil', id=id_usuario))

            # GUARDA A SENHA ATUAL NA TABELA
            cursor.execute("""
                           INSERT INTO senhas_utilizadas (id_usuario, senha)
                           VALUES (?, ?)""", (id_usuario, senha_atual))

            # GERA CRIPITOGRAFIA DA NOVA SENHA
            senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # SELECIONA O USUARIO QUE POSSUI ESTE EMAIL
            cursor.execute("""SELECT id_usuario
                              FROM usuario 
                              WHERE email = ? and id_usuario NOT IN = (
                              SELECT id_usuario FROM usuario
                              where id_usuario = ?)""", (email, id_usuario))


            # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
            email_ja_cadastrado = cursor.fetchone()

            if email_ja_cadastrado:  # SE JA TIVER ESTE EMAIL CADASTRADO
                flash('Erro: Email já utilizado por outro usuário')
                return redirect(url_for('editar_perfil'))

            #ALTERAÇÃO/ EDIÇÃO DOS DADOS DO USUÁRIO
            cursor.execute(""" UPDATE usuario SET nome = ?, email = ?, senha = ?,mao_obra = ?
                               where id_usuario = ?""", (nome, email, senha_hash ,mao_obra, id))

            con.commit() #SALVA AS INFORMAÇÕES
            flash("Usuário editado com sucesso")
            return redirect(url_for('perfil'))

        #REDIRECIONAMENTO PARA A PÁGINA 'EDITAR PERFIL'
        return render_template('editar_perfil.html', usuario=usuario)

    except Exception as e: #SE ACONTECER ALGUM ERRO
            con.rollback() # CANCELA AS INFORMAÇÕES
            flash(f"Ocorreu um error -> {e}")
            return redirect(url_for('perfil'))


    finally:
        cursor.close() #FECHA A CONVERSA COM O BANCO





@app.route('/home') #ROTA INCIAL - LANDING PAGE
def home():
    if 'usuario_nome' not in session: #SE O NOME DO USUÁRIO NÃO ESTIVER NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(url_for('login_usu'))

    return render_template('home.html')

#ROTA QUE PERMITE SAIR DA CONTA
@app.route('/logout')
def logout():
    if 'id_usuario' in session: #SE O USUÁRIO ESTIVER NA SESSÃO - LOGADO
        session.pop('id_usuario') #REMOVE-LO DA LISTA
        flash('Logout com sucesso')
    else:
        flash('Nenhuma conta está logada')

    return redirect(url_for('login_usu'))

if __name__ == '__main__':
    app.run(debug=True)
