from flask import Flask,jsonify,request
from config import config
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps


app=Flask(__name__)

conexion=MySQL(app)

app.config['SECRET_KEY'] = 'estamosloco123'
# Endpoint para actualizar un curso por código


def autenticacion_requerida(f):
    @wraps(f)
    def decorador_autenticacion(*args, **kwargs):
        token = request.headers.get('Authorization')
        # print(app.config['SECRET_KEY'])
        print(token)


        if not token:
            return jsonify({'mensaje': 'Token de autenticación faltante'}), 401

        try:
            print()
            datos_token = jwt.decode(token, app.config['SECRET_KEY'],algorithms=['HS256'])
            

            usuario_id = datos_token['id']
        except Exception as e :
            print(e)
            return jsonify({'mensaje': 'Token de autenticación inválido'}), 401

        return f(usuario_id, *args, **kwargs)

    return decorador_autenticacion


@app.route('/crear_persona', methods=['POST'])
def crear_persona():
    # Obtener los datos de la persona a crear desde el cuerpo de la petición
    nombre = request.json.get('nombre')
    identificacion = request.json.get('identificacion')
    correo = request.json.get('correo')
    
    # Validar que se hayan enviado todos los datos requeridos
    if not nombre or not identificacion or not correo:
        return jsonify({'mensaje': 'Por favor ingrese todos los datos requeridos.'}), 400
    
    # Verificar si la identificación ya existe en la base de datos
    cursor = conexion.connection.cursor()
    cursor.execute('SELECT * FROM persona WHERE identificacion = %s', (identificacion,))
    persona_existente = cursor.fetchone()
    cursor.close()
    if persona_existente:
        return jsonify({'mensaje': 'La identificación ya se encuentra registrada.'}), 409
    
    # Verificar si el correo ya existe en la base de datos
    cursor = conexion.connection.cursor()
    cursor.execute('SELECT * FROM persona WHERE correo = %s', (correo,))
    persona_existente = cursor.fetchone()
    cursor.close()
    if persona_existente:
        return jsonify({'mensaje': 'El correo ya se encuentra registrado.'}), 409
    
    # Generar un ID de usuario aleatorio
    usuario_id = str(uuid.uuid4())
    
    # Generar una contraseña aleatoria a partir de la identificación de la persona
    password = generate_password_hash(identificacion)
    
    # Insertar la persona en la base de datos
    cursor = conexion.connection.cursor()
    cursor.execute('INSERT INTO persona (nombre, identificacion, correo) VALUES (%s, %s, %s)', (nombre, identificacion, correo))
    conexion.connection.commit()
    cursor.close()
    
    # Insertar el usuario en la base de datos
    cursor = conexion.connection.cursor()
    cursor.execute('INSERT INTO usuario (id, correo, contrasena) VALUES (%s, %s, %s)', (usuario_id, correo, password))
    conexion.connection.commit()
    cursor.close()
    
    # Autenticar al usuario recién creado y retornar su información
    cursor = conexion.connection.cursor()
    cursor.execute('SELECT * FROM usuario WHERE correo = %s', (correo,))
    usuario = cursor.fetchone()
    cursor.close()
    if not usuario:
        return jsonify({'mensaje': 'Ha ocurrido un error al autenticar al usuario.'}), 500
    print(app.config['SECRET_KEY'])
    
    secret_key = app.config['SECRET_KEY']
    expiracion = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({'id': usuario[0],'password': usuario[2], 'exp': expiracion}, secret_key, algorithm='HS256')
    
    # Devolver el token como respuesta junto con la información del usuario
    return jsonify({'mensaje': 'La persona se ha creado correctamente y se ha autenticado.', 'usuario': usuario, 'token': token}), 201



@app.route('/curso/<codigo>', methods=['PUT'])
def actualizar_curso(codigo):
    # Obtener los datos del curso a actualizar desde el cuerpo de la solicitud
    datos = request.get_json()
    nombre = datos.get('nombre')
    creditos = datos.get('creditos')

    # Verificar si el curso existe
    cur = conexion.connection.cursor()
    cur.execute("SELECT * FROM curso WHERE codigo=%s", (codigo,))
    curso = cur.fetchone()
    cur.close()

    if not curso:
        return jsonify({'status': 'error', 'message': f'El curso {codigo} no existe'}), 404

    # Generar la consulta SQL para actualizar el curso
    consulta = 'UPDATE curso SET '
    valores = []
    if nombre:
        consulta += 'nombre=%s, '
        valores.append(nombre)
    if creditos is not None:
        consulta += 'creditos=%s, '
        valores.append(creditos)
    consulta = consulta[:-2] + ' WHERE codigo=%s'
    valores.append(codigo)

    # Actualizar el curso en la base de datos
    cur = conexion.connection.cursor()
    cur.execute(consulta, valores)
    conexion.connection.commit()
    cur.close()

    # Devolver una respuesta de éxito
    mensaje = f'El curso {codigo} ha sido actualizado exitosamente'
    return jsonify({'status': 'success', 'message': mensaje}), 200



# @app.route('/cursos', methods=['GET'])
# # @autenticacion_requerida
# def obtener_usuario_autenticado(usuario_id):
#     # Lógica para obtener los detalles del usuario
#     return jsonify({'mensaje': f'Detalles del usuario {usuario_id}'})

@app.route('/cursos')
@autenticacion_requerida
def listarcursos(usuario_id):
    try:
        cursor= conexion.connection.cursor()
        sql="SELECT codigo,nombre,creditos,id FROM curso"
        cursor.execute(sql)
        datos=cursor.fetchall()
        cursor.close()
        print(datos)
        cursos_list = []
        for row in datos:
            cursos = {
                
                'codigo': row[0],
                'nombre': row[1],
                'creditos': row[2],
                'id': row[3],
            }
            cursos_list.append(cursos)

        return jsonify(cursos_list)
    except Exception as ex:
        return "Error"

def page_not_found(error):
    return "<h1>La pagina no existe</h1>"


if __name__ == '__main__':
    app.config.from_object(config['development'])
    app.register_error_handler(404,page_not_found)
    app.run()