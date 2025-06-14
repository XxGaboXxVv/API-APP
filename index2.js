
const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise'); // Usa mysql2/promise
const express = require('express');
const bp = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const moment = require('moment-timezone');
const QRCode = require('qrcode');


const SECRET_KEY = 'your_secret_key'; // Cambia esto por una clave secreta segura
const app = express();
app.use(bp.json());

const mysqlPool = mysql.createPool({
     
     host:'31.170.167.204',
     user:'u569522830_codemasters408',
     password:'Codem@sters123',
     database:'u569522830_lasacacias',
     port:3306,
     multipleStatements: true

});

// SERVIDOR DE CORREO 
const transporter = nodemailer.createTransport({
host: "smtp.hostinger.com",
port: 465,
auth: {
  user: "villalasacacias@villalasacacias.com",
  pass: "Villalasacacias123@"
}
});



const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});




app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const connection = await mysqlPool.getConnection(); // Obtener conexión del pool

        // Consultar el usuario
        const [rows] = await connection.query(
            "SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?",
            [username]
        );
        connection.release(); // Liberar la conexión

        if (rows.length === 0) {
            return res.status(401).send("Usuario no encontrado");
        }

        const user = rows[0];

        // Generar token al inicio
        const generateToken = () => {
            return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
                expiresIn: 8400 // 90 minutos
            });
        };

        const token = generateToken();  // Generar el token

        if (user.ID_ESTADO_USUARIO === 2) {
            return res.status(402).send("Usuario inactivo");
        } else if (user.ID_ESTADO_USUARIO === 3) {
          return res.status(403).send("Usuario bloqueado");
        } else if (user.ID_ESTADO_USUARIO === 4) {
          return res.status(404).send("Usuario Nuevo");
        } else if (user.ID_ESTADO_USUARIO === 5) {
          return res.status(405).send("Usuario pendiente");
        } else {
            const passwordIsValid = bcrypt.compareSync(password, user.CONTRASEÑA);

            if (!passwordIsValid) {
                const connection = await mysqlPool.getConnection(); // Obtener nueva conexión del pool
                await connection.query(
                    "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE EMAIL = ?",
                    [username]
                );

                const [paramRows] = await connection.query(
                  "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = ?",
                  ['INTENTOS_FALLIDOS']
              );
              connection.release();
               // Liberar la conexión

                const maxLoginAttempts = parseInt(paramRows[0].VALOR, 10);
                if (user.INTENTOS_FALLIDOS + 1 >= maxLoginAttempts + 1) {
                    const connection = await mysqlPool.getConnection(); // Obtener nueva conexión del pool
                    await connection.query(
                        "UPDATE TBL_MS_USUARIO SET ID_ESTADO_USUARIO = 3 WHERE EMAIL = ?",
                        [username]
                    );
                    connection.release(); // Liberar la conexión

                    return res.status(403).send("Usuario ha sido bloqueado por múltiples intentos fallidos");
                } else {
                    return res.status(401).send("Contraseña incorrecta");
                }
            } else {
                // Actualizar los campos INTENTOS_FALLIDOS y PRIMER_INGRESO después de verificar la contraseña
                const connection = await mysqlPool.getConnection(); // Obtener nueva conexión del pool
                await connection.query(
                    "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = 0, PRIMER_INGRESO = IF(PRIMER_INGRESO IS NULL, CONVERT_TZ(NOW(), @@session.time_zone, '-06:00'), PRIMER_INGRESO) WHERE EMAIL = ?",
                    [username]
                );
                  if (user.CODIGO_2FA === 1) {
                    // Generar y enviar código de verificación
                    const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase(); // Código de 6 dígitos en mayúsculas

                    await connection.query(
                        "UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = ? WHERE EMAIL = ?",
                        [verificationCode, username]
                    );

                    const mailOptions = {
                      from: 'villalasacacias@villalasacacias.com',
                      to: username,
                      subject: 'Código de Verificación 2FA',
                      html: `
                        <p>Estimado/a usuario/a,</p>
                        <p>Como parte de nuestro proceso de autenticación en dos pasos (2FA), te hemos enviado un código de verificación único para asegurar que solo tú puedas acceder a tu cuenta.</p>
                        <p>Tu código de verificación es:</p>
                        <p style="font-size: 24px; font-weight: bold;">${verificationCode}</p>
                        <p>Por favor, ingresa este código en la pantalla de verificación para completar el proceso de autenticación.</p>
                        <p>Si no solicitaste este código, te recomendamos que cambies tu contraseña y te pongas en contacto con nuestro equipo de administracion de Villas Las Acacias.</p>
                        <p>Gracias por tu cooperación.</p>
                        <p>Atentamente,</p>
                        <p>El equipo de administración de Villas Las Acacias</p>
                      `
                    };

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.log(error);
                            return res.status(500).send("Error al enviar el código de verificación");
                        }
                        // Enviar respuesta con el token y redirección para la verificación de código
                        res.status(200).json({ token, id_usuario: user.ID_USUARIO, redirect: '/validar_codigo_2fa' });
                    });
                } else {
                    // Si no se requiere 2FA, simplemente retorna el token y redirige
                    res.status(200).json({ token, id_usuario: user.ID_USUARIO, redirect: '/pantalla_principal' });
                }

                connection.release(); // Liberar la conexión
            }
        }
    } catch (err) {
        console.error('Error en la operación de base de datos:', err);
        res.status(500).send("Error interno del servidor");
    }
});



function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send("No token provided");
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send("Failed to authenticate token");
    }

    req.userId = decoded.id;
    next();
  });
}



app.get('/protected', verifyToken, (req, res) => {
  res.status(200).send("Access granted");
});


//*************** Verificacion de 2FA *********
app.post('/validar_codigo_2fa', async (req, res) => {
  const { ID_USUARIO, CODIGO_VERIFICACION } = req.body;

  try {
    const connection = await mysqlPool.getConnection();
    
    const [results] = await connection.query('SELECT * FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [ID_USUARIO]);
    connection.release();

    if (results.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const user = results[0];

    if (user.CODIGO_VERIFICACION !== CODIGO_VERIFICACION) {
      return res.status(400).json({ message: 'Código de verificación incorrecto' });
    }

    await connection.query('UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL WHERE ID_USUARIO = ?', [ID_USUARIO]);

    const generateToken = () => {
      return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
        expiresIn: 5400 // 90 minutos
      });
    };

    const token = generateToken();  // Generar el token

    res.status(200).json({ token, id_usuario: user.ID_USUARIO, redirect: '/pantalla_principal' });
  } catch (err) {
    console.error('Error al verificar el código:', err);
    res.status(500).json({ message: 'Error al verificar el código' });
  }
});



//Actualizar el estado de 2FA
app.post('/set2FAStatus', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const { enabled } = req.body;
    if (typeof enabled !== 'number' || (enabled !== 0 && enabled !== 1)) {
      return res.status(400).json({ message: 'Valor inválido para 2FA' });
    }

    const connection = await mysqlPool.getConnection();
    await connection.query('UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?', [enabled, userId]);
    connection.release();

    res.json({ message: 'Estado de 2FA actualizado correctamente' });
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error al verificar el token' });
  }
});



//********** GET CODIGO 2FA ********
app.get('/get2FAStatus', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT CODIGO_2FA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [userId]);
    connection.release();

    if (results.length > 0) {
      res.json({ enabled: results[0].CODIGO_2FA });
    } else {
      res.status(404).json({ message: 'Usuario no encontrado' });
    }
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error al verificar el token' });
  }
});



//********** REGISTRO *********** 

const secretKey = crypto.randomBytes(32); // Clave secreta de 256 bits
const iv = Buffer.alloc(16, 0); // IV de 16 bytes

// Cifrado
function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Descifrado
function decrypt(encryptedText) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.post('/register', async (req, res) => {
  const { NOMBRE_USUARIO, EMAIL, CONTRASEÑA } = req.body;

  console.log('Iniciando proceso de registro.');

  if (!NOMBRE_USUARIO || !EMAIL || !CONTRASEÑA) {
    console.error('Faltan campos requeridos:', { NOMBRE_USUARIO, EMAIL, CONTRASEÑA });
    return res.status(400).json({ message: 'Todos los campos son requeridos' });
  }

  try {
    console.log('Cifrando contraseña.');
    const hashedPassword = await bcrypt.hash(CONTRASEÑA, 8);
    const connection = await mysqlPool.getConnection(); // Obtener conexión del pool
    console.log('Conexión a la base de datos establecida.');

        // Verificar si el nombre de usuario ya existe
        const [existingUser] = await connection.query('SELECT NOMBRE_USUARIO, PRIMER_INGRESO_COMPLETADO FROM TBL_MS_USUARIO WHERE NOMBRE_USUARIO = ?', [NOMBRE_USUARIO]);

        if (existingUser.length > 0) {
          const usuarioExistente = existingUser[0];
    
          if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 1) {
            console.error('Persona ya registrada y primer ingreso completado.');
            connection.release();
            return res.status(400).json({ message: 'Nombre de persona ya registrado' });
          }
        }

    // Verificar si el correo ya está registrado y el estado de PRIMER_INGRESO_COMPLETADO
    const [results] = await connection.query('SELECT NOMBRE_USUARIO, PRIMER_INGRESO_COMPLETADO, ID_USUARIO FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL]);

    if (results.length > 0) {
      console.log('Correo ya registrado. Verificando estado de primer ingreso.');
      const usuarioExistente = results[0];

      if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 1) {
        console.error('El usuario ya ha completado el primer ingreso.');
        connection.release(); // Liberar la conexión
        return res.status(400).json({ message: 'Correo ya registrado' });
      } 
      if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 0) {
        console.log('Actualizando datos del usuario existente 0000.');
        const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.alloc(16, 0));
        let encryptedVerificationCode = cipher.update(verificationCode, 'utf8', 'hex');
        encryptedVerificationCode += cipher.final('hex');

        // Actualizar datos en TBL_MS_USUARIO
        const updateQuery = 'UPDATE TBL_MS_USUARIO SET NOMBRE_USUARIO = ?, CONTRASEÑA = ?, CODIGO_VERIFICACION = ?, ID_ROL = ?, ID_ESTADO_USUARIO = ?, CODIGO_2FA = ? WHERE EMAIL = ?';
        await connection.query(updateQuery, [NOMBRE_USUARIO, hashedPassword, encryptedVerificationCode, 2, 5, 1, EMAIL]);
        console.log('Datos del usuario actualizados en TBL_MS_USUARIO.');

        // Capturar el nombre de usuario asociado con el correo
        const existingName = usuarioExistente.NOMBRE_USUARIO;

        // Actualizar el NOMBRE_PERSONA en TBL_PERSONAS
        const updatePersonaQuery = 'UPDATE TBL_PERSONAS SET NOMBRE_PERSONA = ? WHERE NOMBRE_PERSONA = ?';
        await connection.query(updatePersonaQuery, [NOMBRE_USUARIO, existingName]);
        console.log('Nombre de persona actualizado en TBL_PERSONAS.');

        // Configurar y enviar el correo electrónico
        const mailOptions = {
          from: 'villalasacacias@villalasacacias.com',
          to: EMAIL,
          subject: 'Código de Verificación',
          html: `
            <p>Estimado/a,</p>
            <p>Hemos recibido una solicitud para verificar tu cuenta en nuestro sistema. Para completar el proceso, por favor utiliza el siguiente código de verificación:</p>
            <p style="font-size: 24px; font-weight: bold;">${verificationCode}</p>
            <p>Este código es válido por un tiempo limitado, por lo que te recomendamos usarlo lo antes posible.</p>
            <p>Si no solicitaste esta verificación, por favor ignora este mensaje.</p>
            <p>Gracias por confiar en nosotros.</p>
            <p>Atentamente,</p>
            <p>El equipo de soporte de Vila Las Acacias</p>
          `
        };

        transporter.sendMail(mailOptions, (err) => {
          if (err) {
            console.error('Error al enviar el correo:', err);
            return res.status(500).json({ message: 'Error al enviar el correo de verificación' });
          }

          console.log('Correo de verificación enviado con éxito.');
          // Generar el token
          const token = jwt.sign({ id: usuarioExistente.ID_USUARIO }, SECRET_KEY, {
            expiresIn: 1800 // 30 minutos
          });

          // Enviar respuesta al cliente
          res.status(201).json({
            token: token,
            id_usuario: usuarioExistente.ID_USUARIO,
            message: 'Usuario registrado exitosamente. Por favor verifica tu correo.'
          });
        });

        //connection.release();
        return;
      }
    }

    // Si el correo no existe, proceder con el registro normal
    console.log('Correo no registrado previamente. Procediendo con el registro.');
    const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase();
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.alloc(16, 0));
    let encryptedVerificationCode = cipher.update(verificationCode, 'utf8', 'hex');
    encryptedVerificationCode += cipher.final('hex');

    const query = 'INSERT INTO TBL_MS_USUARIO (NOMBRE_USUARIO, EMAIL, CONTRASEÑA, CODIGO_VERIFICACION, ID_ROL, ID_ESTADO_USUARIO, CODIGO_2FA) VALUES (?, ?, ?, ?, ?, ?, ?)';
    const [insertResults] = await connection.query(query, [NOMBRE_USUARIO, EMAIL, hashedPassword, encryptedVerificationCode, 2, 5, 1]);
    const userId = insertResults.insertId; // Obtener el ID del usuario recién insertado
    console.log('Usuario registrado en TBL_MS_USUARIO con ID:', userId);

    // Insertar NOMBRE_USUARIO en la tabla TBL_PERSONAS
    const personaQuery = 'INSERT INTO TBL_PERSONAS (NOMBRE_PERSONA) VALUES (?)';
    await connection.query(personaQuery, [NOMBRE_USUARIO]);
    console.log('Nombre de usuario insertado en TBL_PERSONAS.');

    connection.release();
    console.log('Conexión liberada.');

    // Configurar y enviar el correo electrónico
    const mailOptions = {
      from: 'villalasacacias@villalasacacias.com',
      to: EMAIL,
      subject: 'Código de Verificación',
      html: `
        <p>Estimado/a,</p>
        <p>Hemos recibido una solicitud para verificar tu cuenta en nuestro sistema. Para completar el proceso, por favor utiliza el siguiente código de verificación:</p>
        <p style="font-size: 24px; font-weight: bold;">${verificationCode}</p>
        <p>Este código es válido por un tiempo limitado, por lo que te recomendamos usarlo lo antes posible.</p>
        <p>Si no solicitaste esta verificación, por favor ignora este mensaje.</p>
        <p>Gracias por confiar en nosotros.</p>
        <p>Atentamente,</p>
        <p>El equipo de soporte de Vila Las Acacias</p>
      `
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Error al enviar el correo:', err);
        return res.status(500).json({ message: 'Error al enviar el correo de verificación' });
      }

      console.log('Correo de verificación enviado con éxito.');
      // Generar el token
      const token = jwt.sign({ id: userId }, SECRET_KEY, {
        expiresIn: 1800 // 30 minutos
      });

      // Enviar respuesta al cliente
      res.status(201).json({
        token: token,
        id_usuario: userId,
        message: 'Usuario registrado exitosamente. Por favor verifica tu correo.'
      });
    });
  } catch (err) {
    console.error('Error al procesar el registro:', err);
    res.status(500).json({ message: 'Error al procesar el registro' });
  }
});

//******** Verificar registro ********
app.post('/verify', async (req, res) => {
  const { EMAIL, CODIGO_VERIFICACION } = req.body;

  try {
    const connection = await mysqlPool.getConnection();
    
    const [results] = await connection.query('SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL]);
    
    if (results.length === 0) {
      connection.release();
      return res.status(400).json({ message: 'Correo no encontrado' });
    }

    const user = results[0];

    if (user.INTENTOS_FALLIDOS >= 5) {
      await connection.query('DELETE FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL]);
      connection.release();
      return res.status(400).json({ message: 'Has alcanzado el límite de intentos de verificación.' });
    }

    if (user.CODIGO_VERIFICACION === null) {
      connection.release();
      return res.status(400).json({ message: 'No hay un código de verificación disponible para este usuario' });
    }

    // Configurar el descifrado usando los mismos parámetros que en el cifrado
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.alloc(16, 0));
    let decryptedVerificationCode;

    try {
      decryptedVerificationCode = decipher.update(user.CODIGO_VERIFICACION, 'hex', 'utf8');
      decryptedVerificationCode += decipher.final('utf8');
    } catch (error) {
      console.error('Error al descifrar el código:', error);
      connection.release();
      return res.status(500).json({ message: 'Error al procesar el código de verificación' });
    }

    if (CODIGO_VERIFICACION !== decryptedVerificationCode) {
      await connection.query('UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE EMAIL = ?', [EMAIL]);
      connection.release();
      return res.status(400).json({ message: 'Código de verificación incorrecto' });
    }

    const primerIngreso = moment().tz("America/Tegucigalpa").format('YYYY-MM-DD HH:mm:ss');

    const [parametroResults] = await connection.query('SELECT VALOR FROM TBL_MS_PARAMETROS WHERE ID_PARAMETRO = 2');
    const diasVencimiento = parseInt(parametroResults[0].VALOR, 10);
    const fechaVencimiento = moment().add(diasVencimiento, 'days').format('YYYY-MM-DD');

    await connection.query('UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL, PRIMER_INGRESO = ?, FECHA_VENCIMIENTO = ?, ID_ESTADO_USUARIO = 5, INTENTOS_FALLIDOS = 0 WHERE EMAIL = ?', [primerIngreso, fechaVencimiento, EMAIL]);

    connection.release();

    res.status(200).json({ message: 'Correo verificado exitosamente' });
  } catch (error) {
    console.error('Error al procesar la verificación:', error);
    res.status(500).json({ message: 'Error al procesar la verificación' });
  }
});

//*********** RESTABLECER CONTRASENA    *********** 
app.post('/restablecer_contrasena', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'El campo de correo electrónico es requerido.' });
    }

    try {
        const connection = await mysqlPool.getConnection(); // Obtener conexión del pool

        // Verificar si el usuario existe
        const [userResults] = await connection.query('SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?', [email]);

        if (userResults.length === 0) {
            connection.release(); // Liberar la conexión
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const estadoUsuario = userResults[0].ID_ESTADO_USUARIO;

        if ([2, 4, 5].includes(estadoUsuario)) {
          return res.status(405).json({ message: 'Estado de usuario denegado.' });
        }

        const tempPassword = crypto.randomBytes(4).toString('hex');
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);

        // Eliminar cualquier entrada existente para el usuario en TBL_REINICIO_CONTRASEÑA
        await connection.query('DELETE FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?', [email]);

        // Insertar la nueva entrada en TBL_REINICIO_CONTRASEÑA
        await connection.query(
            'INSERT INTO TBL_REINICIO_CONTRASEÑA (TOKEN, EMAIL) VALUES (?, ?)',
            [hashedTempPassword, email]
        );

        connection.release(); // Liberar la conexión

        // Configurar y enviar el correo electrónico
        const mailOptions = {
            from: 'villalasacacias@villalasacacias.com',
            to: email,
            subject: 'Restablecimiento de Contraseña',
            html: `
                <p>Estimado/a usuario/a,</p>
                <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta. Para proceder, por favor utiliza la siguiente contraseña temporal:</p>
                <p style="font-size: 24px; font-weight: bold;">${tempPassword}</p>
                <p>Te recomendamos que inicies sesión con esta contraseña temporal y la cambies de inmediato para proteger tu cuenta.</p>
                <p>Si no solicitaste este restablecimiento, te recomendamos que ignores este correo y te pongas en contacto con nuestro equipo de administración de Villas Las Acacias inmediatamente.</p>
                <p>Gracias por tu atención.</p>
                <p>Atentamente,</p>
                <p>El equipo de administración de Villas Las Acacias</p>
            `
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: 'Error al enviar el correo' });
            }
            return res.status(200).json({ message: 'Correo enviado con éxito' });
        });

    } catch (err) {
        console.error('Error al procesar el restablecimiento de contraseña:', err);
        res.status(500).json({ message: 'Error al procesar la solicitud' });
    }
});


  
  
app.post('/verificar_contrasena_temporal', async (req, res) => {
  const { email, tempPassword } = req.body;

  if (!email || !tempPassword) {
    return res.status(400).json({ message: 'El correo electrónico y la contraseña temporal son requeridos' });
  }

  try {
    const connection = await mysqlPool.getConnection();
    
    // Verificar el token
    const [tokenResults] = await connection.query('SELECT * FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?', [email]);

    if (tokenResults.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Token no encontrado' });
    }

    let token = tokenResults[0]; // Cambiado const por let
    const isMatch = await bcrypt.compare(tempPassword, token.TOKEN);

    if (!isMatch) {
      connection.release();
      return res.status(400).json({ message: 'Contraseña temporal incorrecta' });
    }

    // Obtener los datos del usuario
    const [userResults] = await connection.query('SELECT ID_USUARIO, CONTRASEÑA FROM TBL_MS_USUARIO WHERE EMAIL = ?', [email]);

    if (userResults.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const user = userResults[0];

    // Insertar en TBL_MS_HIST_CONTRASEÑA
    await connection.query('INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)', [user.ID_USUARIO, user.CONTRASEÑA]);

    // Actualizar la contraseña, estado e intentos fallidos en TBL_MS_USUARIO
    const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
    await connection.query('UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ?, ID_ESTADO_USUARIO = 1, INTENTOS_FALLIDOS = 0 WHERE ID_USUARIO = ?', [hashedTempPassword, user.ID_USUARIO]);

    connection.release();

    // Generar el token
    token = jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
      expiresIn: 8400 // 90 minutos
    });

    res.status(200).json({ token, id_usuario: user.ID_USUARIO });
  } catch (error) {
    console.error('Error al procesar la verificación de la contraseña temporal:', error);
    res.status(500).json({ message: 'Error al procesar la verificación de la contraseña temporal' });
  }
});


  
  // ************  Ruta para actualizar la contraseña   **********
 app.post('/cambiar_contrasena', async (req, res) => {
  const { actual, nueva } = req.body;

  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verificar y decodificar el token
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const connection = await mysqlPool.getConnection();

    // Consultar la contraseña actual del usuario desde la base de datos
    const [userResults] = await connection.query('SELECT CONTRASEÑA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [userId]);

    if (userResults.length === 0) {
      connection.release();
      console.error('Usuario no encontrado');
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const contrasenaActual = userResults[0].CONTRASEÑA;

    // Verificar si la nueva contraseña es igual a la actual
    const isSamePassword = await bcrypt.compare(nueva, contrasenaActual);
    if (isSamePassword) {
      connection.release();
      console.error('No puedes reutilizar la contraseña actual');
      return res.status(400).json({ message: 'No puedes reutilizar la contraseña actual' });
    }

    // Verificar si la contraseña actual proporcionada es correcta
    const isMatch = await bcrypt.compare(actual, contrasenaActual);
    if (!isMatch) {
      connection.release();
      console.error('Contraseña actual incorrecta');
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }
    // Hashear la nueva contraseña
    const nuevaHashed = await bcrypt.hash(nueva, 10);
    // Insertar la contraseña actual en la tabla TBL_MS_HIST_CONTRASEÑA
    await connection.query('INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)', [userId, contrasenaActual]);
    // Actualizar la nueva contraseña en la tabla TBL_MS_USUARIO
    await connection.query('UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ? WHERE ID_USUARIO = ?', [nuevaHashed, userId]);

    connection.release();

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error al cambiar la contraseña:', error);
    res.status(500).json({ message: 'Error al cambiar la contraseña' });
  }
});

// ************   Ruta para registrar una visita
app.post('/registrar_visitas', async (req, res) => {
  const { usuarioId, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, isRecurrentVisitor, FECHA_VENCIMIENTO } = req.body;

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO usando el usuarioId
    const [usuarioResults] = await connection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId]);

    if (usuarioResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario]);

    if (personaResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Persona no encontrada' });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;

    // Obtener el valor del parámetro con ID_PARAMETRO = QR_VENCIMIENTO
    const [parametroResults] = await connection.query('SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = "QR_VENCIMIENTO"');

    if (parametroResults.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Parámetro no encontrado' });
    }

    const horas = parametroResults[0].VALOR;
    const fechaActual = moment().tz('America/Tegucigalpa');
    const fechaCalculada = fechaActual.add(horas, 'hours').format('YYYY-MM-DD HH:mm:ss');

    // Convertir FECHA_VENCIMIENTO al formato 'YYYY-MM-DD HH:mm:ss'
    const fechaVencimiento = moment(FECHA_VENCIMIENTO, 'DD-MM-YYYY HH:mm').format('YYYY-MM-DD HH:mm:ss');

    let insertQuery, insertParams;

    if (isRecurrentVisitor) {
      const fechaActual = moment().tz('America/Tegucigalpa');
      insertQuery = 'INSERT INTO TBL_VISITANTES_RECURRENTES (ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?, ?)';
      insertParams = [ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaActual.format('YYYY-MM-DD HH:mm:ss'), fechaVencimiento];
    } else {
      insertQuery = 'INSERT INTO TBL_REGVISITAS (ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA) VALUES (?, ?, ?, ?, ?, ?)';
      insertParams = [ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaCalculada];
    }

    const [result] = await connection.query(insertQuery, insertParams);

    // Insertar en la tabla TBL_BITACORA_VISITA
    const ID_VISITANTE = result.insertId; // Obtener el ID del visitante registrado

    let insertBitacoraQuery, insertBitacoraParams;

    if (isRecurrentVisitor) {
      const fechaActual = moment().tz('America/Tegucigalpa');
      insertBitacoraQuery = 'INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTES_RECURRENTES, NUM_PERSONA, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)';
      insertBitacoraParams = [ID_PERSONA, ID_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaActual.format('YYYY-MM-DD HH:mm:ss'), fechaVencimiento];
    } else {
      const fechaActual = moment().tz('America/Tegucigalpa');
      insertBitacoraQuery = 'INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTE, NUM_PERSONA, NUM_PLACA, FECHA_HORA,FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)';
      insertBitacoraParams = [ID_PERSONA, ID_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaActual.format('YYYY-MM-DD HH:mm:ss'), fechaCalculada];
    }

    await connection.query(insertBitacoraQuery, insertBitacoraParams);

    // Obtener la información adicional del QR
    const [personaInfoResults] = await connection.query(`
      SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
      FROM TBL_PERSONAS p
      LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
      LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
      WHERE p.ID_PERSONA = ?`, [ID_PERSONA]);

    if (personaInfoResults.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Información del QR no encontrada' });
    }

    const personaInfo = personaInfoResults[0];
    let qrData;

    if (isRecurrentVisitor) {
      qrData = {
        Residente: personaInfo.NOMBRE_PERSONA,
        DNI_Residente: personaInfo.DNI_PERSONA,
        Contacto: personaInfo.CONTACTO,
        Condominio: personaInfo.ID_CONDOMINIO,
        NOMBRE_VISITANTE,
        DNI_VISITANTE,
        NUM_PERSONAS,
        NUM_PLACA,
        FECHA_VENCIMIENTO: fechaVencimiento
      };
    } else {
      qrData = {
        ID_VISITANTE,
        Residente: personaInfo.NOMBRE_PERSONA,
        DNI_Residente: personaInfo.DNI_PERSONA,
        Contacto: personaInfo.CONTACTO,
        Condominio: personaInfo.ID_CONDOMINIO,
        NOMBRE_VISITANTE,
        DNI_VISITANTE,
        NUM_PERSONAS,
        NUM_PLACA,
        FECHA_HORA: fechaCalculada
      };
    }

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(JSON.stringify(qrData), (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    connection.release();

    res.status(201).json({
      message: isRecurrentVisitor ? 'Visitante recurrente registrado exitosamente' : 'Visita registrada exitosamente',
      qrCode: qrUrl
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

//Validar el QR por los eventos 
app.post('/validateQR', async (req, res) => {
  // Desestructurar el ID_VISITANTE del cuerpo
  const { ID_VISITANTE } = req.body;

  // Validar que el ID_VISITANTE esté presente
  if (!ID_VISITANTE) {
    return res.status(400).json({ message: 'ID de visitante no proporcionado' });
  }

  try {
    const connection = await mysqlPool.getConnection();

    // Verificar si el visitante existe en la base de datos
    const [visitanteResults] = await connection.query(
      'SELECT ESTADO_QR FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?',
      [ID_VISITANTE]
    );

    if (visitanteResults.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'ID de visitante no encontrado' });
    }

    const estadoQR = visitanteResults[0].ESTADO_QR;

    // Obtener el parámetro QR_EVENTOS
    const [parametroResults] = await connection.query(
      "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = 'QR_EVENTOS'"
    );

    if (parametroResults.length === 0) {
      connection.release();
      return res.status(500).json({ message: 'Parámetro QR_EVENTOS no configurado' });
    }

    const valorQREventos = parametroResults[0].VALOR;

    // Validar si el código QR ya fue escaneado
    if (estadoQR == valorQREventos) {
      connection.release();
      return res.status(400).json({ message: 'Código QR ya escaneado' });
    }

    // Respuesta exitosa
    connection.release();
    return res.status(200).json({ message: 'Código QR válido' });
  } catch (error) {
    console.error('Error al validar el código QR:', error);
    return res.status(500).json({ message: 'Error interno al validar el código QR' });
  }
});



//Incrementar el estado del qr 
app.post('/incrementarEstadoQR', async (req, res) => {
  const {ID_VISITANTE} = req.body;

    if (!ID_VISITANTE) {
      console.error('Datos recibidos:');
    return res.status(400).json({ message: 'ID de visitante no proporcionado' });
    
  }
  try {
    // Obtener una conexión del pool
    const connection = await mysqlPool.getConnection();

    // Consultar el estado del QR en TBL_REGVISITAS
    const [visitanteResults] = await connection.query(
      'SELECT ESTADO_QR FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?',
      [ID_VISITANTE]
    );

    if (visitanteResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Visitante no encontrado' });
    }

    const estadoQR = visitanteResults[0].ESTADO_QR;

    // Incrementar el estado del QR
    const nuevoEstadoQR = estadoQR + 1;
    await connection.query(
      'UPDATE TBL_REGVISITAS SET ESTADO_QR = ? WHERE ID_VISITANTE = ?',
      [nuevoEstadoQR, ID_VISITANTE]
    );

    // Liberar la conexión
    connection.release();

    return res.status(200).json({ message: 'Estado QR incrementado exitosamente'});
  } catch (error) {
    console.error('Error al incrementar el estado del QR:', error);
    return res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Crear un endpoint para obtener todos los anuncios
app.get('/anuncios_eventos', async (req, res) => {
  const usuarioId = req.query.usuario_id;

  const query = `
    SELECT ID_ANUNCIOS_EVENTOS, TITULO, DESCRIPCION, IMAGEN, FECHA_HORA 
    FROM TBL_ANUNCIOS_EVENTOS 
    WHERE ID_ESTADO_ANUNCIO_EVENTO = 1 
    AND ID_ANUNCIOS_EVENTOS NOT IN (
        SELECT ID_ANUNCIOS_EVENTOS FROM TBL_ANUNCIOS_OCULTOS WHERE ID_USUARIO = ?
    )
    ORDER BY FECHA_HORA DESC`;

  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query(query, [usuarioId]);
    connection.release();
    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener los anuncios:', error);
    res.status(500).send('Error al obtener los anuncios');
  }
});


// Endpoint para ocultar un anuncio
app.post('/ocultar_anuncio', async (req, res) => {
  const { usuarioId, anuncioId } = req.body;

  console.log('Datos recibidos:', req.body);

  const query = `
    INSERT INTO TBL_ANUNCIOS_OCULTOS (ID_USUARIO, ID_ANUNCIOS_EVENTOS) 
    VALUES (?, ?)`;

  try {
    const connection = await mysqlPool.getConnection();
    await connection.query(query, [usuarioId, anuncioId]);
    connection.release();
    res.status(200).send('Anuncio ocultado exitosamente');
  } catch (error) {
    console.error('Error al ocultar el anuncio:', error);
    res.status(500).send('Error al ocultar el anuncio');
  }
});



// Crear un endpoint para obtener los datos del perfil del usuario
app.get('/perfil', async (req, res) => {
  const usuarioId = req.query.usuario_id;

  const query = `
    SELECT NOMBRE_USUARIO, EMAIL, ID_ROL 
    FROM TBL_MS_USUARIO 
    WHERE ID_USUARIO = ?`;

  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query(query, [usuarioId]);
    connection.release();

    if (results.length > 0) {
      res.status(200).json(results[0]);
    } else {
      console.log(`Usuario con ID ${usuarioId} no encontrado`);
      res.status(404).send('Usuario no encontrado');
    }
  } catch (error) {
    console.error('Error al obtener el perfil del usuario:', error);
    res.status(500).send('Error al obtener el perfil del usuario');
  }
});



//********** Consultar Reservaciones *********
app.get('/consultar_reservaciones', async (req, res) => {
  const usuarioId = req.query.usuario_id;

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId]);

    if (!usuarioResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario]);

    if (!personaResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Persona no encontrada' });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;

    // Obtener todas las reservas para ese ID_PERSONA
    const query = `
SELECT 
  p.NOMBRE_PERSONA, 
  i.NOMBRE_INSTALACION, 
  e.DESCRIPCION, 
  r.HORA_FECHA, 
  r.TIPO_EVENTO
  FROM 
  TBL_RESERVAS r
  INNER JOIN 
  TBL_PERSONAS p ON r.ID_PERSONA = p.ID_PERSONA
  INNER JOIN 
  TBL_INSTALACIONES i ON r.ID_INSTALACION = i.ID_INSTALACION
  INNER JOIN 
  TBL_ESTADO_RESERVA e ON r.ID_ESTADO_RESERVA = e.ID_ESTADO_RESERVA
  WHERE 
  r.ID_PERSONA = ? AND 
    r.HORA_FECHA >= CURDATE()
    ORDER BY 
    r.HORA_FECHA ASC;
  `;
    const [reservasResults] = await connection.query(query, [ID_PERSONA]);
    connection.release();

    res.json(reservasResults);
  } catch (error) {
    console.error('Error al obtener las reservas:', error);
    res.status(500).json({ error: 'Error al obtener las reservas' });
  }
});



//********** Consultar Visitas *********
app.get('/consultar_visitas', async (req, res) => {
  const usuarioId = req.query.usuario_id;

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId]);

    if (!usuarioResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario]);

    if (!personaResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Persona no encontrada' });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;

    // Consultar los registros de visitas en TBL_REGVISITAS
    const queryRegVisitas = `
    SELECT NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, 
           DATE_FORMAT(FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
           NULL AS FECHA_VENCIMIENTO, 
           'No recurrente' AS TIPO
    FROM TBL_REGVISITAS 
    WHERE ID_PERSONA = ?`; 
  
  const queryVisitantesRecurrentes = `
    SELECT NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, 
           DATE_FORMAT(FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
           DATE_FORMAT(FECHA_VENCIMIENTO, '%d/%m/%Y %H:%i') AS FECHA_VENCIMIENTO, 
           'Recurrente' AS TIPO
    FROM TBL_VISITANTES_RECURRENTES 
    WHERE ID_PERSONA = ?`;
  

    const [regVisitasResults] = await connection.query(queryRegVisitas, [ID_PERSONA]);
    const [visitantesRecurrentesResults] = await connection.query(queryVisitantesRecurrentes, [ID_PERSONA]);

    // Combinar los resultados de ambas consultas
    const resultados = [...regVisitasResults, ...visitantesRecurrentesResults];

    connection.release();

    // Retornar los resultados a la aplicación Flutter
    res.json(resultados);
  } catch (error) {
    console.error('Error al consultar visitas:', error);
    res.status(500).json({ error: 'Error al consultar visitas' });
  }
});

// Ruta para consultar reservaciones futuras
app.get('/consulta_reservaciones_futuras', async (req, res) => {
  let connection;
  try {
    // Obtener una conexión del pool
    connection = await mysqlPool.getConnection();

    // Consulta SQL 
    const query = `
      SELECT 
          r.ID_RESERVA, 
          r.ID_PERSONA, 
          i.NOMBRE_INSTALACION, 
          e.DESCRIPCION AS ESTADO_RESERVA, 
          r.TIPO_EVENTO, 
          r.HORA_FECHA
      FROM 
          TBL_RESERVAS r
      JOIN 
          TBL_INSTALACIONES i ON r.ID_INSTALACION = i.ID_INSTALACION
      JOIN 
          TBL_ESTADO_RESERVA e ON r.ID_ESTADO_RESERVA = e.ID_ESTADO_RESERVA
      WHERE 
          r.HORA_FECHA >= CURDATE()
      ORDER BY 
          r.HORA_FECHA ASC;
    `;

    // Ejecutar la consulta
    const [results] = await connection.query(query);

    // Retornar los resultados a la aplicación Flutter
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).send('Error en el servidor');
  } finally {
    if (connection) {
      // Liberar la conexión de vuelta al pool
      connection.release();
    }
  }
});

// ***********   Ruta para obtener los horarios de las reservaciones
app.get('/obtener_horarios', async (req, res) => {
  let connection;
  try {
    // Obtener una conexión del pool
    connection = await mysqlPool.getConnection();

    // Consulta SQL
    const query = `
      SELECT 
        PARAMETRO, VALOR
      FROM 
        TBL_MS_PARAMETROS
      WHERE 
        PARAMETRO IN ('HORARIO_LUNES_VIERNES_MANAÑA', 'HORARIO_LUNES_VIERNES_TARDE', 'HORARIO_SABADO_MANAÑA', 'HORARIO_SABADO_TARDE', 'HORARIO_DOMINGO_MANAÑA', 'HORARIO_DOMINGO_TARDE')
    `;

    // Ejecutar la consulta
    const [results] = await connection.query(query);

    // Formatear los resultados en una lista
    const horarios = [
      { 
        "Días": "Lunes a viernes", 
        "Horarios": `${results.find(row => row.PARAMETRO === 'HORARIO_LUNES_VIERNES_MANAÑA')?.VALOR || 'No disponible'} y ${results.find(row => row.PARAMETRO === 'HORARIO_LUNES_VIERNES_TARDE')?.VALOR || 'No disponible'}` 
      },
      { 
        "Días": "Sábado", 
        "Horarios": `${results.find(row => row.PARAMETRO === 'HORARIO_SABADO_MANAÑA')?.VALOR || 'No disponible'} y ${results.find(row => row.PARAMETRO === 'HORARIO_SABADO_TARDE')?.VALOR || 'No disponible'}` 
      },
      { 
        "Días": "Domingo", 
        "Horarios": `${results.find(row => row.PARAMETRO === 'HORARIO_DOMINGO_MANAÑA')?.VALOR || 'No disponible'} y ${results.find(row => row.PARAMETRO === 'HORARIO_DOMINGO_TARDE')?.VALOR || 'No disponible'}` 
      }
    ];

    // Retornar los horarios formateados
    res.json(horarios);

  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).send('Error en el servidor');
  } finally {
    if (connection) {
      // Liberar la conexión de vuelta al pool
      connection.release();
    }
  }
});



//********* Consultar familia ************
app.get('/consultar_familia', async (req, res) => {
  const usuarioId = req.query.usuario_id;

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId]);

    if (!usuarioResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA y el ID_CONDOMINIO de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query('SELECT ID_PERSONA, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario]);

    if (!personaResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Persona no encontrada' });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;
    const ID_CONDOMINIO = personaResults[0].ID_CONDOMINIO;

    // Consultar todas las personas con el mismo ID_CONDOMINIO
    const queryPersonas = `
      SELECT 
        p.NOMBRE_PERSONA, 
        p.DNI_PERSONA, 
        c.DESCRIPCION AS CONTACTO,
        tp.DESCRIPCION AS TIPO_PERSONA,
        ep.DESCRIPCION AS ESTADO_PERSONA,
        par.DESCRIPCION AS PARENTESCO,
        con.DESCRIPCION AS CONDOMINIO
      FROM TBL_PERSONAS p
      LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
      LEFT JOIN TBL_TIPO_PERSONAS tp ON p.ID_TIPO_PERSONA = tp.ID_TIPO_PERSONA
      LEFT JOIN TBL_ESTADO_PERSONA ep ON p.ID_ESTADO_PERSONA = ep.ID_ESTADO_PERSONA
      LEFT JOIN TBL_PARENTESCOS par ON p.ID_PARENTESCO = par.ID_PARENTESCO
      LEFT JOIN TBL_CONDOMINIOS con ON p.ID_CONDOMINIO = con.ID_CONDOMINIO
      WHERE p.ID_CONDOMINIO = ?;
    `;

    const [personasResults] = await connection.query(queryPersonas, [ID_CONDOMINIO]);

    connection.release();

    // Retornar los resultados a la aplicación Flutter
    res.json(personasResults);
  } catch (error) {
    console.error('Error al consultar la familia:', error);
    res.status(500).json({ error: 'Error al consultar la familia' });
  }
});



//********** Insertar Reserva *****
app.post('/nueva_reserva', async (req, res) => {
  const { usuarioId, nombreInstalacion, tipoEvento, horaFecha } = req.body;

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO usando el usuarioId
    const [usuarioResults] = await connection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId]);

    if (!usuarioResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener datos de la persona
    const [personaResults] = await connection.query('SELECT ID_PERSONA, NOMBRE_PERSONA, DNI_PERSONA, ID_CONTACTO, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario]);

    if (!personaResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Persona no encontrada' });
    }

    const { ID_PERSONA, NOMBRE_PERSONA, DNI_PERSONA, ID_CONTACTO, ID_CONDOMINIO } = personaResults[0];

    // Obtener la DESCRIPCION del contacto
    const [contactoResults] = await connection.query('SELECT DESCRIPCION FROM TBL_CONTACTOS WHERE ID_CONTACTO = ?', [ID_CONTACTO]);

    if (!contactoResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Contacto no encontrado' });
    }

    const P_CONTACTO = contactoResults[0].DESCRIPCION;

    // Obtener la DESCRIPCION del condominio
    const [condominioResults] = await connection.query('SELECT DESCRIPCION FROM TBL_CONDOMINIOS WHERE ID_CONDOMINIO = ?', [ID_CONDOMINIO]);

    if (!condominioResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Condominio no encontrado' });
    }

    const P_CONDOMINIO = condominioResults[0].DESCRIPCION;

    // Buscar ID_INSTALACION por nombre
    const [instalacionResults] = await connection.query('SELECT ID_INSTALACION FROM TBL_INSTALACIONES WHERE NOMBRE_INSTALACION = ?', [nombreInstalacion]);

    if (!instalacionResults.length) {
      connection.release();
      return res.status(404).json({ error: 'Instalación no encontrada' });
    }

    const ID_INSTALACION = instalacionResults[0].ID_INSTALACION;
    
    const horaFechaYMDHM = moment.tz(horaFecha, 'DD-MM-YYYY HH:mm', 'America/Tegucigalpa').format('YYYY-MM-DD HH:mm:ss');

   // const horaFechaYMDHM = moment(horaFecha, 'DD-MM-YYYY HH:mm').format('YYYY-MM-DD HH:mm:ss');

    // Determinar el día de la semana
    const diaSemana = new Date(horaFechaYMDHM).getDay();
    let jornada = '';

    // Determinar si la reserva es por la mañana o la tarde
    const horaReserva = new Date(horaFechaYMDHM).getHours();

    if (horaReserva < 13) {
      jornada = diaSemana >= 1 && diaSemana <= 5 ? 'HORARIO_LUNES_VIERNES_MANAÑA' : 
                diaSemana === 6 ? 'HORARIO_SABADO_MANAÑA' : 
                'HORARIO_DOMINGO_MANAÑA';
    } else {
      jornada = diaSemana >= 1 && diaSemana <= 5 ? 'HORARIO_LUNES_VIERNES_TARDE' : 
                diaSemana === 6 ? 'HORARIO_SABADO_TARDE' : 
                'HORARIO_DOMINGO_TARDE';
    }

    // Obtener los horarios permitidos para la jornada seleccionada
    const [parametrosResults] = await connection.query('SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = ?', [jornada]);

    if (!parametrosResults.length) {
      connection.release();
      return res.status(500).json({ error: 'No se pudo obtener el horario permitido' });
    }

    const [horaInicio, horaFin] = parametrosResults[0].VALOR.split('-').map(h => h.trim());

    // Verificar si la hora solicitada está dentro del horario permitido
    const hora = horaFechaYMDHM.split(' ')[1];
    if (hora < horaInicio || hora > horaFin) {
      connection.release();
      return res.status(400).json({ error: 'El horario ingresado no está permitido según los parámetros configurados' });
    }

    // Verificar si ya existe una reserva en el mismo día y en la misma jornada para la misma instalación
    const [reservaResults] = await connection.query(
      `SELECT * FROM TBL_RESERVAS 
       WHERE ID_INSTALACION = ? 
       AND DATE(HORA_FECHA) = DATE(?) 
       AND TIME(HORA_FECHA) BETWEEN TIME(?) AND TIME(?)`,
      [ID_INSTALACION, horaFechaYMDHM, horaInicio, horaFin]
    );

    if (reservaResults.length > 0) {
      connection.release();
      return res.status(400).json({ error: 'Horario ya reservado' });
    }

    // Insertar la reserva si no hay conflicto
    const [insertResult] = await connection.query(
      'INSERT INTO TBL_RESERVAS (ID_PERSONA, ID_INSTALACION, ID_ESTADO_RESERVA, TIPO_EVENTO, HORA_FECHA) VALUES (?, ?, 3, ?, ?)',
      [ID_PERSONA, ID_INSTALACION, tipoEvento, horaFechaYMDHM]
    );
    //pasar de formato la fecha de la reservación
    const horaFechaDMAHMS = moment(horaFechaYMDHM).format('DD-MM-YYYY HH:mm');

    // Obtener los correos de los administradores
    const [adminEmails] = await mysqlPool.query('SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL = 4');

    const emailList = adminEmails.map(row => row.EMAIL);
    const mailOptions = {
      from: 'villalasacacias@villalasacacias.com',
      to: emailList,
      subject: 'Nueva reservación',
      html: `
        <p>Estimados Administradores,</p>
        <p>Nos complace informarles que se ha solicitado una nueva reservación:</p>
        <p><strong>Nombre:</strong> ${NOMBRE_PERSONA}</p>
        <p><strong>DNI:</strong> ${DNI_PERSONA}</p>
        <p><strong>Contacto:</strong> ${P_CONTACTO}</p>
        <p><strong>Numero de casa:</strong> ${P_CONDOMINIO}</p>
        <p><strong>Instalación:</strong> ${nombreInstalacion}</p>
        <p><strong>Tipo de Evento:</strong> ${tipoEvento}</p>
        <p><strong>Fecha y Hora:</strong> ${horaFechaDMAHMS}</p>
        <p>Les solicitamos brindar el apoyo necesario para que la nueva reservación se ejecute de manera adecuada.</p>
        <p>Atentamente,</p>
        <p>El equipo de administración de Villas Las Acacias</p>
      `
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Error al enviar el correo:', err);
        return res.status(500).json({ error: 'Error al enviar el correo' });
      }
      console.log('Correo enviado a:', emailList);
    });

    connection.release();
    res.status(201).json({ message: 'Reserva creada exitosamente', reservaId: insertResult.insertId });
  } catch (error) {
    console.error('Error al crear la reserva:', error);
    res.status(500).json({ error: 'Error al crear la reserva' });
  }
});





// ******* Tipos de Instalaciones *******
app.get('/instalaciones', async (req, res) => {
  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT NOMBRE_INSTALACION FROM TBL_INSTALACIONES');
    connection.release();
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).json({ error: 'Error al ejecutar la consulta' });
  }
});



//Actualizar el estado de 2FA
app.post('/set2FAStatus', async (req, res) => {
  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verificar y decodificar el token
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const { enabled } = req.body;
    if (typeof enabled !== 'number' || (enabled !== 0 && enabled !== 1)) {
      return res.status(400).json({ message: 'Valor inválido para 2FA' });
    }

    // Actualizar el estado de 2FA en la base de datos
    const connection = await mysqlPool.getConnection();
    await connection.query('UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?', [enabled, userId]);
    connection.release();

    res.json({ message: 'Estado de 2FA actualizado correctamente' });
  } catch (error) {
    console.error('Error al verificar el token o actualizar el estado de 2FA:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});



//************** GET para estado de la persona *************
app.get('/personas', async (req, res) => {
  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT DESCRIPCION FROM TBL_ESTADO_PERSONA');
    connection.release();
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).json({ error: 'Error al ejecutar la consulta' });
  }
});


app.get('/contacto', async (req, res) => {
  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT DESCRIPCION FROM TBL_TIPO_CONTACTO');
    connection.release();
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).json({ error: 'Error al ejecutar la consulta' });
  }
});



app.get('/parentesco', async (req, res) => {
  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT DESCRIPCION FROM TBL_PARENTESCOS');
    connection.release();
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).json({ error: 'Error al ejecutar la consulta' });
  }
});

app.get('/condominio', async (req, res) => {
  try {
    const connection = await mysqlPool.getConnection();
    const [results] = await connection.query('SELECT DESCRIPCION FROM TBL_CONDOMINIOS');
    connection.release();
    res.json(results);
  } catch (err) {
    console.error('Error al ejecutar la consulta:', err);
    res.status(500).json({ error: 'Error al ejecutar la consulta' });
  }
});


//********* NUEVA PERSONA *********
app.post("/nueva_persona", async (req, res) => {
  const {
    usuarioId,
    P_DNI,
    P_TIPO_CONTACTO,
    P_CONTACTO,
    P_PARENTESCO,
    P_CONDOMINIO, // Este es la descripción del condominio
  } = req.body;

  if (
    !usuarioId ||
    !P_DNI ||
    !P_TIPO_CONTACTO ||
    !P_CONTACTO ||
    !P_PARENTESCO ||
    !P_CONDOMINIO
  ) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  try {
    const connection = await mysqlPool.getConnection();

    // Obtener ID_CONDOMINIO y USUARIOS_POR_CASA desde la descripción
    const [condominioResults] = await connection.query(
      "SELECT ID_CONDOMINIO, USUARIOS_POR_CASA FROM TBL_CONDOMINIOS WHERE DESCRIPCION = ?",
      [P_CONDOMINIO]
    );

    if (condominioResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Condominio no encontrado" });
    }

    const ID_CONDOMINIO = condominioResults[0].ID_CONDOMINIO;
    const usuariosPorCasa = condominioResults[0].USUARIOS_POR_CASA;

    // Contar usuarios registrados en el condominio
    const [usuariosRegistradosResults] = await connection.query(
      "SELECT COUNT(*) AS totalUsuarios FROM TBL_PERSONAS WHERE ID_CONDOMINIO = ?",
      [ID_CONDOMINIO]
    );

    const totalUsuariosRegistrados =
      usuariosRegistradosResults[0].totalUsuarios;

    if (totalUsuariosRegistrados >= usuariosPorCasa) {
      connection.release();
      return res
        .status(400)
        .json({ error: "Cantidad máxima de usuarios ya registrados" });
    }

    // Obtener nombre del usuario
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener ID_PERSONA
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;

    // Verificar si es necesario asignar administrador
    const [adminResults] = await connection.query(
      "SELECT COUNT(*) AS adminCount FROM TBL_PERSONAS WHERE ID_CONDOMINIO = ? AND ID_PADRE = 1",
      [ID_CONDOMINIO]
    );

    const adminCount = adminResults[0].adminCount;
    const isAdminRequired = adminCount === 0;

    // Obtener ID_TIPO_CONTACTO
    const [tipoContactoResults] = await connection.query(
      "SELECT ID_TIPO_CONTACTO FROM TBL_TIPO_CONTACTO WHERE DESCRIPCION = ?",
      [P_TIPO_CONTACTO]
    );

    // Obtener ID_PARENTESCO
    const [parentescoResults] = await connection.query(
      "SELECT ID_PARENTESCO FROM TBL_PARENTESCOS WHERE DESCRIPCION = ?",
      [P_PARENTESCO]
    );

    if (!tipoContactoResults.length || !parentescoResults.length) {
      connection.release();
      return res.status(405).json({ error: "Datos no encontrados" });
    }

    const ID_TIPO_CONTACTO = tipoContactoResults[0].ID_TIPO_CONTACTO;
    const ID_PARENTESCO = parentescoResults[0].ID_PARENTESCO;

    // Insertar contacto
    const [contactoResults] = await connection.query(
      "INSERT INTO TBL_CONTACTOS (ID_TIPO_CONTACTO, DESCRIPCION) VALUES (?, ?)",
      [ID_TIPO_CONTACTO, P_CONTACTO]
    );

    const ID_CONTACTO = contactoResults.insertId;

    // Actualizar persona
    const queryParams = [
      P_DNI,
      ID_CONTACTO,
      1,
      ID_PARENTESCO,
      ID_CONDOMINIO,
      ID_PERSONA,
    ];

    const updatePersonaQuery = isAdminRequired
      ? `
      UPDATE TBL_PERSONAS
      SET DNI_PERSONA = ?, ID_CONTACTO = ?,
      ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?,
      ID_CONDOMINIO = ?, ID_PADRE = 1
      WHERE ID_PERSONA = ?`
      : `
      UPDATE TBL_PERSONAS
      SET DNI_PERSONA = ?, ID_CONTACTO = ?,
      ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?,
      ID_CONDOMINIO = ?, ID_PADRE = NULL
      WHERE ID_PERSONA = ?`;

    await connection.query(updatePersonaQuery, queryParams);

    // Marcar primer ingreso completado
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET PRIMER_INGRESO_COMPLETADO = 1 WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    connection.release();

    // Enviar correo si es el primer administrador global
    if (isAdminRequired) {
      const [adminEmails] = await mysqlPool.query(
        "SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4)"
      );

      const emailList = adminEmails.map((row) => row.EMAIL);

      const mailOptions = {
        from: "villalasacacias@villalasacacias.com",
        to: emailList,
        subject: "Registro de Nuevo Administrador de la Casa",
        html: `
          <p>Estimados Administradores,</p>
          <p>Se ha registrado un nuevo administrador para la casa:</p>
          <p><strong>Nombre:</strong> ${nombreUsuario}</p>
          <p><strong>Contacto:</strong> ${P_CONTACTO}</p>
          <p><strong>Numero de casa:</strong> ${P_CONDOMINIO}</p>
          <p>Saludos,</p>
          <p>Villas Las Acacias</p>
        `,
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) {
          console.error("Error al enviar el correo:", err);
        } else {
          console.log("Correo enviado a:", emailList);
        }
      });
    }

    // ********* NUEVA LÓGICA: Notificar a administradores del condominio *********
    const [adminPersonas] = await mysqlPool.query(
      `SELECT NOMBRE_PERSONA FROM TBL_PERSONAS 
       WHERE ID_CONDOMINIO = ? AND ID_PADRE = 1`,
      [ID_CONDOMINIO]
    );

    if (adminPersonas.length > 0) {
      const nombresAdmin = adminPersonas.map((p) => p.NOMBRE_PERSONA);

      const [correosAdminCondominio] = await mysqlPool.query(
        `SELECT EMAIL FROM TBL_MS_USUARIO 
         WHERE NOMBRE_USUARIO IN (?)`,
        [nombresAdmin]
      );

      const correos = correosAdminCondominio.map((c) => c.EMAIL);

      if (correos.length > 0) {
        const mailOptionsAdmin = {
          from: "villalasacacias@villalasacacias.com",
          to: correos,
          subject: "Nuevo usuario registrado en su casa",
          html: `
            <p>Estimado(s) Administrador(es),</p>
            <p>Se ha registrado un nuevo usuario en la casa <strong>${P_CONDOMINIO}</strong>.</p>
            <p><strong>Nombre:</strong> ${nombreUsuario}</p>
            <p><strong>DNI:</strong> ${P_DNI}</p>
            <p><strong>Contacto:</strong> ${P_CONTACTO}</p>
            <p>Saludos cordiales,<br>Villas Las Acacias</p>
          `,
        };

        transporter.sendMail(mailOptionsAdmin, (err) => {
          if (err) {
            console.error("Error al enviar correo a administradores de la casa:", err);
          } else {
            console.log("Correo enviado a administradores de la casa:", correos);
          }
        });
      } else {
        console.warn("No se encontraron correos de administradores de la casa.");
      }
    } else {
      console.warn("No hay administradores registrados en la casa.");
    }

    res.status(201).json({
      success: true,
      message:
        "Persona actualizada correctamente y PRIMER_INGRESO_COMPLETADO establecido en 1",
    });
  } catch (err) {
    console.error("Error al procesar la solicitud:", err);
    res.status(500).json({ error: "Error al procesar la solicitud" });
  }
});


//********** Actualizar lo PRIMER_INGRESO_COMPLETADO ********
app.put('/desactivarPersona', async (req, res) => {
  const { ID_USUARIO } = req.body;

  if (!ID_USUARIO) {
    return res.status(400).json({ error: 'ID_USUARIO es requerido' });
  }

  const updateQuery = 'UPDATE TBL_MS_USUARIO SET PRIMER_INGRESO_COMPLETADO = 1 WHERE ID_USUARIO = ?';

  try {
    const connection = await mysqlPool.getConnection();
    const [result] = await connection.query(updateQuery, [ID_USUARIO]);

    connection.release();

    if (result.affectedRows > 0) {
      res.status(200).json({ success: true, message: 'PRIMER_INGRESO_COMPLETADO actualizado correctamente' });
    } else {
      res.status(404).json({ error: 'No se encontró el usuario con el ID_USUARIO proporcionado' });
    }
  } catch (err) {
    console.error('Error al actualizar PRIMER_INGRESO_COMPLETADO:', err);
    res.status(500).json({ error: 'Error al actualizar PRIMER_INGRESO_COMPLETADO' });
  }
});

//Identificar el ID_PADRE del residente y mostrarle las solicitudes
app.get('/solicitudes', async (req, res) => {
    const usuarioId = req.query.usuario_id;
    //const {usuarioId}= req.body;
    console.log(usuarioId);

    if (!usuarioId) {
        return res.status(400).json({ error: 'Se requiere usuario_id' });
    }

    try {
        const connection = await mysqlPool.getConnection(); // Obtener conexión del pool

        // Obtener el nombre de usuario
        const [usuarioResults] = await connection.query(
            'SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?',
            [usuarioId]
        );

        if (usuarioResults.length === 0) {
            connection.release(); // Liberar la conexión
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

        // Obtener el ID_PERSONA usando el nombreUsuario
        const [personaResults] = await connection.query(
            'SELECT ID_PERSONA, ID_PADRE, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?',
            [nombreUsuario]
        );

        if (personaResults.length === 0) {
            connection.release(); // Liberar la conexión
            return res.status(404).json({ message: 'Persona no encontrada' });
        }

        const { ID_PERSONA, ID_PADRE, ID_CONDOMINIO } = personaResults[0];

        // Verificar si el usuario es administrador (ID_PADRE debe ser 1)
        if (ID_PADRE !== 1) {
            connection.release(); // Liberar la conexión
          return res.status(403).json({ message: 'No tienes los permisos para poder ingresar' });
        }

        // Obtener todos los nombres en ese ID_CONDOMINIO que tengan el estado pendiente (ID_ESTADO_USUARIO = 5)
        const [residentesResults] = await connection.query(
            `SELECT 
              p.NOMBRE_PERSONA, 
              p.DNI_PERSONA, 
              c.DESCRIPCION AS CONTACTO,
              par.DESCRIPCION AS PARENTESCO,
              con.DESCRIPCION AS CONDOMINIO,
              u.ID_USUARIO
             FROM TBL_PERSONAS p
             JOIN TBL_MS_USUARIO u ON p.NOMBRE_PERSONA COLLATE utf8mb4_unicode_ci = u.NOMBRE_USUARIO COLLATE utf8mb4_unicode_ci
             LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
             LEFT JOIN TBL_PARENTESCOS par ON p.ID_PARENTESCO = par.ID_PARENTESCO
             LEFT JOIN TBL_CONDOMINIOS con ON p.ID_CONDOMINIO = con.ID_CONDOMINIO
             WHERE p.ID_CONDOMINIO = ? AND u.ID_ESTADO_USUARIO = 5`,
            [ID_CONDOMINIO]
        );

        connection.release(); // Liberar la conexión

        if (residentesResults.length === 0) {
            return res.status(200).json({ message: 'No hay residentes pendientes de aprobación' });
        }

        res.status(200).json({ residentesPendientes: residentesResults });
    } catch (err) {
        console.error('Error al obtener las solicitudes de residentes:', err);
        res.status(500).json({ error: 'Error al obtener las solicitudes de residentes' });
    }
});

//***** Acepta las solicitudes solo el que es ID_PADRE
app.post('/aceptar', async (req, res) => {
    const { idUsuario } = req.body;

    if (!idUsuario) {
        return res.status(400).json({ error: 'Se requiere idUsuario' });
    }

    console.log('Datos recibidos en /aceptar:', req.body);

    try {
        const [result] = await mysqlPool.query(
            'UPDATE TBL_MS_USUARIO SET ID_ESTADO_USUARIO = 1 WHERE ID_USUARIO = ?',
            [idUsuario]
        );

        res.status(200).send('Solicitud aceptada');
    } catch (err) {
        console.error('Error al aceptar la solicitud:', err);
        res.status(500).send('Error al aceptar la solicitud');
    }
});

//***** Rechaza las solicitudes solo el que es ID_PADRE
app.post('/rechazar', async (req, res) => {
  const { idUsuario } = req.body;

  if (!idUsuario) {
      return res.status(400).json({ error: 'Se requiere idUsuario' });
  }

  console.log('Datos recibidos en /rechazar:', req.body);

  const connection = await mysqlPool.getConnection();

  try {
      // Iniciar la transacción
      await connection.beginTransaction();

      // Obtener el NOMBRE_USUARIO y EMAIL asociado al ID_USUARIO
      const [userResult] = await connection.query(
          'SELECT NOMBRE_USUARIO, EMAIL FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?',
          [idUsuario]
      );

      if (userResult.length === 0) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const { NOMBRE_USUARIO: nombreUsuario, EMAIL: email } = userResult[0];

      // Eliminar el registro de TBL_PERSONAS basado en el NOMBRE_USUARIO
      await connection.query(
          'DELETE FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?',
          [nombreUsuario]
      );

      // Eliminar el registro de TBL_MS_USUARIO basado en el ID_USUARIO
      await connection.query(
          'DELETE FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?',
          [idUsuario]
      );

      // Confirmar la transacción
      await connection.commit();

      // Configurar el correo electrónico
      const mailOptions = {
          from: 'villalasacacias@villalasacacias.com',
          to: email,
          subject: 'Solicitud Rechazada',
          html: `
              <p>Estimad@ ${nombreUsuario},</p>
              <p>Lamentamos informarle que su solicitud ha sido rechazada en Villa Las Acacias.</p>
              <p>Si tiene alguna pregunta o necesita más información, no dude en ponerse en contacto con la administración.</p>
              <p>Atentamente,</p>
              <p>El equipo de administración de Villas Las Acacias</p>
          `
      };

      // Enviar el correo
      transporter.sendMail(mailOptions, (err) => {
          if (err) {
              console.error('Error al enviar el correo:', err);
              return res.status(500).json({ error: 'Error al enviar el correo' });
          }
          console.log('Correo enviado a:', email);
      });

      res.status(200).send('Solicitud rechazada y correo enviado correctamente');
  } catch (err) {
      // Revertir los cambios en caso de error
      await connection.rollback();
      console.error('Error al rechazar la solicitud:', err);
      res.status(500).send('Error al rechazar la solicitud');
  } finally {
      // Liberar la conexión
      connection.release();
  }
});


//Confirmar las visitas del QR
app.post('/confirmar_visita', async (req, res) => {
  console.log('Datos recibidos:', req.body); 
 const { nombreResidente, nombreVisitante, numeroPersonas } = req.body;

  try {
      // Obtener una conexión del pool
      const connection = await mysqlPool.getConnection();

      // Consulta para buscar el correo electrónico del residente
      const [rows] = await connection.execute(
          'SELECT EMAIL FROM TBL_MS_USUARIO WHERE NOMBRE_USUARIO = ?',
          [nombreResidente] // Usamos el parámetro nombreResidente
      );

      // Liberar la conexión después de usarla
      connection.release();

      if (rows.length === 0) {
          return res.status(404).json({ error: 'Residente no encontrado' });
      }

      // Capturar el correo electrónico del residente
      const emailResidente = rows[0].EMAIL;
      const fechaActual = moment.tz('America/Tegucigalpa').format('DD-MM-YYYY HH:mm');

      // Redactar el correo
      const mailOptions = {
          from: 'villalasacacias@villalasacacias.com',
          to: emailResidente, // Enviar el correo al residente encontrado
          subject: 'Confirmación de Visita',
          html: `
              <p>Estimado ${nombreResidente},</p>
              <p>Le informamos que ha llegado un visitante:</p>
              <p><strong>Nombre del visitante:</strong> ${nombreVisitante}</p>
              <p><strong>Número de personas:</strong> ${numeroPersonas}</p>
              <p><strong>Fecha y hora de llegada:</strong> ${fechaActual}</p>
              <p>Atentamente,</p>
              <p>El equipo de administración de Villas Las Acacias</p>
          `
      };

      // Enviar el correo
      await transporter.sendMail(mailOptions);
      console.log('Correo enviado a:', emailResidente);
      return res.status(200).json({ message: 'Correo enviado exitosamente' });

  } catch (err) {
      console.error('Error al realizar la operación:', err);
      return res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

// Ruta para enviar correos del comportamiento de los visitantes
app.post('/notificarMotivo', async (req, res) => {
  const {
    nombreResidente,
    dniResidente,
    contacto,
    condominio,
    nombreVisitante,
    dniVisitante,
    numeroPersonas,
    motivo,
  } = req.body;

  try {
    // Obtener correos de administradores con ID_ROL en (1, 4)
    const [adminEmailsResult] = await mysqlPool.query(
      'SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4)'
    );
    const adminEmails = adminEmailsResult.map((row) => row.EMAIL);

    // Obtener el correo del residente por nombre
    const [residentEmailResult] = await mysqlPool.query(
      'SELECT EMAIL FROM TBL_MS_USUARIO WHERE NOMBRE_USUARIO = ?',
      [nombreResidente]
    );
    const fechaActual = moment.tz('America/Tegucigalpa').format('DD-MM-YYYY HH:mm');

    const residentEmail = residentEmailResult.length
      ? residentEmailResult[0].EMAIL
      : null;

    if (!residentEmail) {
      return res.status(404).json({ error: 'No se encontró el correo del residente' });
    }

    // Crear el contenido del correo
    const emailContent = `
      <p>Estimados Administradores y Residente,</p>
      <p>Por este medio les notificamos sobre un incidente relacionado con el comportamiento de una visita:</p>
      <p><strong>Motivo:</strong> ${motivo}</p>
      <p><strong>Fecha y hora:</strong> ${fechaActual}</p>
      <p><strong>Detalles del Visitante:</strong></p>
      <ul>
        <li><strong>Nombre:</strong> ${nombreVisitante}</li>
        <li><strong>DNI:</strong> ${dniVisitante}</li>
        <li><strong>Número de personas:</strong> ${numeroPersonas}</li>
      </ul>
      <p><strong>Detalles del Residente Asociado:</strong></p>
      <ul>
        <li><strong>Nombre:</strong> ${nombreResidente}</li>
        <li><strong>DNI:</strong> ${dniResidente}</li>
        <li><strong>Contacto:</strong> ${contacto}</li>
        <li><strong>Numero de casa:</strong> ${condominio}</li>
      </ul>
      <p>Les solicitamos su colaboración para resolver esta situación y tomar las medidas necesarias para evitar incidentes futuros.</p>
      <p>Atentamente,</p>
      <p>El equipo de administración de Villas Las Acacias</p>
    `;

    // Opciones de envío
    const mailOptions = {
      from: 'villalasacacias@villalasacacias.com',
      to: [...adminEmails, residentEmail],
      subject: 'Comportamiento de Visita',
      html: emailContent,
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Error al enviar el correo:', err);
        return res.status(500).json({ error: 'Error al enviar el correo' });
      }
      console.log('Correo enviado a:', [...adminEmails, residentEmail]);
      res.status(200).json({ message: 'Correo enviado exitosamente' });
    });
  } catch (error) {
    console.error('Error al procesar la solicitud:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
