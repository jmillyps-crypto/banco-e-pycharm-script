
from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'Aqui_e_a_chave_da_turma_a'

#CONEXÃO COM O BANCO
host = 'localhost'
database = r'C:\Users\marco\Downloads\BANCO.FDB'
user = 'SYSDBA'
password = 'SYSDBA'

con = fdb.connect(host=host, database=database, user=user, password=password)

@app.route('/') #ROTA INCIAL - LANDING PAGE
def index():
    return render_template('index.html')

@app.route('/cadastro_usu') #ROTA QUE DIRECIONA PARA A PÁGINA CADASTRO DE USUÁRIO
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

@app.route('/cadastrar', methods=['POST'])  #ROTA QUE REALIZA O CADASTRO
def cadastrar():
    nome = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']
    mao_obra = request.form['mao_obra']

    if not senha_forte(senha):
        flash("Senha fraca! Precisa conter 8 ou mais caracteres, pelo menos uma letra maiúscula, um número e um caracter especial")
        return redirect(url_for('cadastro_usu'))

    cursor = con.cursor()  # ABRINDO O CURSOR

    try:  #TRATAMENTO DE ERRO
        cursor.execute("""SELECT 1
                          FROM usuario u
                          WHERE nome = ?""", (nome,))

        usuario = cursor.fetchone() #CONFERINDO SE JÁ TEM ESTE USUÁRIO

        if usuario: #SE TIVER USUÁRIO
            flash('Erro: Usuário já cadastrado')
            return redirect(url_for('cadastro_usu'))

        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        #EXECUÇÃO DO INSERT
        cursor.execute(""" INSERT INTO usuario (nome, email, senha, mao_obra, tentativas)
                           VALUES (?, ?, ?, ?, ?)""", (nome, email, senha_hash,mao_obra, 0))

        con.commit() #SALVA AS INFORMAÇÕES
        flash("Usuário cadastrado com sucesso")
        return redirect(url_for('login_usu'))


    except Exception as e:
        flash(f"Ocorreu um error -> {e}")
        con.rollback() #CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('cadastro_usu'))

    finally:
        cursor.close() #FECHAR A CONVERSA COM O BANCO

@app.route('/login_usu', methods=['GET', 'POST'])
def login_usu():
    if request.method == 'GET':
        return render_template('login_usuario.html')

    email = request.form['email']
    senha = request.form['senha']

    cursor = con.cursor()
    try:
        cursor.execute("""SELECT id_usuario,nome, senha, tentativas
        FROM usuario u
        WHERE u.email = ? """, (email,))

        usuario = cursor.fetchone()

        if not usuario:
            flash("Usuário não encontrado")
            return redirect(url_for('login_usu'))

        id_usuario,nome, senha_hash, tentativas = usuario

        if tentativas >= 3:
            flash("Você passou de 3 tentativas! Sua conta foi bloqueada.")
            return redirect(url_for('login_usu'))

        if usuario:
            if bcrypt.check_password_hash(senha_hash, senha):

                cursor.execute("""UPDATE usuario
                set tentativas = 0
                where id_usuario = ?""", (id_usuario,))

                con.commit()

                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome

                flash('Conta logada')
                return redirect(url_for('home'))

            else:

                cursor.execute("""UPDATE usuario
                set tentativas = tentativas + 1
                where id_usuario = ?""", (id_usuario,))

                con.commit()

                if tentativas + 1 >= 3:
                    flash('Você passou de 3 tentativas! Sua conta foi bloqueada.')
                else:
                    flash('Email ou senha inválida')
                return redirect(url_for('login_usu'))
        return render_template('login_usu.html')

    except Exception as e:
        flash(f"Ocorreu um error -> {e}")
        con.rollback()
        return redirect(url_for('login_usu'))
    finally:
        cursor.close()


@app.route('/perfil') #ROTA DA PAGINA DE PERFIL DO USUARIO
def perfil():

    if 'id_usuario' not in session:
        return redirect(url_for('login_usu'))

    cursor = con.cursor()
    try:
        cursor.execute("""SELECT id_usuario,nome, email, senha, mao_obra
        FROM usuario u
        WHERE id_usuario = ? """, (session['id_usuario'],))

        usuario = cursor.fetchone()


        if not usuario:
            flash('Usuário não encontrado')
            return redirect(url_for('home'))

        id_usuario,nome, email, senha_hash, mao_obra = usuario

        return render_template(
            'perfil.html',
            nome=nome,
            email=email,
            mao_obra=mao_obra
        )

    except Exception as e:
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close()





@app.route('/home') #ROTA INCIAL - LANDING PAGE
def home():
    if 'usuario_nome' not in session:
        return redirect(url_for('login_usu'))

    return render_template('home.html')

@app.route('/logout') #limpar da lista
def logout():
    if 'id_usuario' in session:
        session.pop('id_usuario')
        flash('Logout com sucesso')
    else:
        flash('Nenhuma conta está logada')

    return redirect(url_for('login_usu'))

if __name__ == '__main__':
    app.run(debug=True)