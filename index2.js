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
    host: 'srv1059.hstgr.io',
    user: 'u729991132_root',
    password: 'Dragonb@ll2',
    database: 'u729991132_railway',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 50, // Ajusta según el rendimiento y necesidades
    queueLimit: 0
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const connection = await mysqlPool.getConnection();
        
        const [rows] = await connection.query(
            "SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?",
            [username]
        );
        connection.release(); // Libera la conexión de la piscina

        if (rows.length === 0) {
            return res.status(404).send("Usuario no encontrado");
        }

        const user = rows[0];

        // Generar token al inicio
        const generateToken = () => {
            return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
                expiresIn: 8400 // 90 minutos
            });
        };

        const token = generateToken();  // Generar el token

        if (user.ID_ESTADO_USUARIO === 5) {
            const connection = await mysqlPool.getConnection();
            const [adminRows] = await connection.query(
                "SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL = 1"
            );
            connection.release(); // Libera la conexión de la piscina

            const adminEmails = adminRows.map(admin => admin.EMAIL);
            return res.status(402).json({
                message: "Comuníquese con los administradores para el uso de la aplicación",
                adminEmails: adminEmails,
                token: token  // Enviar token en la respuesta
            });
        } else if (user.ID_ESTADO_USUARIO === 2) {
            return res.status(403).send("Usuario inactivo");
        } else if (user.ID_ESTADO_USUARIO === 3) {
            return res.status(403).send("Usuario ha sido bloqueado");
        } else {
            const passwordIsValid = bcrypt.compareSync(password, user.CONTRASEÑA);

            if (!passwordIsValid) {
                const connection = await mysqlPool.getConnection();
                await connection.query(
                    "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE EMAIL = ?",
                    [username]
                );

                const [paramRows] = await connection.query(
                    "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE ID_PARAMETRO = 1"
                );
                connection.release(); // Libera la conexión de la piscina

                const maxLoginAttempts = parseInt(paramRows[0].VALOR, 10);
                if (user.INTENTOS_FALLIDOS + 1 >= maxLoginAttempts + 1) {
                    const connection = await mysqlPool.getConnection();
                    await connection.query(
                        "UPDATE TBL_MS_USUARIO SET ID_ESTADO_USUARIO = 3 WHERE EMAIL = ?",
                        [username]
                    );
                    connection.release(); // Libera la conexión de la piscina

                    return res.status(403).send("Usuario ha sido bloqueado por múltiples intentos fallidos");
                } else {
                    return res.status(401).send("Contraseña incorrecta");
                }
            } else {
                // Actualizar los campos INTENTOS_FALLIDOS y PRIMER_INGRESO después de verificar la contraseña
                const connection = await mysqlPool.getConnection();
                await connection.query(
                    "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = 0, PRIMER_INGRESO = IF(PRIMER_INGRESO IS NULL, CONVERT_TZ(NOW(), @@session.time_zone, '-06:00'), PRIMER_INGRESO) WHERE EMAIL = ?",
                    [username]
                );

                if (user.ID_ESTADO_USUARIO === 1 && user.PRIMER_INGRESO_COMPLETADO === 0) {
                    // Redirigir al usuario a la página de completar información
                    res.status(200).json({ token, id_usuario: user.ID_USUARIO, redirect: '/completar_persona' });
                } else if (user.CODIGO_2FA === 1) {
                    // Generar y enviar código de verificación
                    const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase(); // Código de 6 dígitos en mayúsculas

                    await connection.query(
                        "UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = ? WHERE EMAIL = ?",
                        [verificationCode, username]
                    );

                    const mailOptions = {
                        from: 'no-reply@yourdomain.com',
                        to: username,
                        subject: 'Código de Verificación 2FA',
                        text: `Tu código de verificación es: ${verificationCode}`
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

                connection.release(); // Libera la conexión de la piscina
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
app.post('/validar_codigo_2fa', (req, res) => {
  const { ID_USUARIO, CODIGO_VERIFICACION } = req.body;

  // Consulta para obtener los datos del usuario
  mysqlConnection.query('SELECT * FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [ID_USUARIO], (err, results) => {
    if (err) {
      console.error('Error al verificar el código:', err);
      return res.status(500).json({ message: 'Error al verificar el código' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const user = results[0];

    // Verifica si el código proporcionado coincide con el almacenado en la base de datos
    if (user.CODIGO_VERIFICACION !== CODIGO_VERIFICACION) {
      return res.status(400).json({ message: 'Código de verificación incorrecto' });
    }

    // Si el código es correcto, elimina el código de verificación del usuario
    mysqlConnection.query(
      'UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL WHERE ID_USUARIO = ?',
      [ID_USUARIO],
      (err) => {
        if (err) {
          console.error('Error al actualizar el código de verificación:', err);
          return res.status(500).json({ message: 'Error al actualizar el código de verificación' });
        }

        // Generar un nuevo token para el usuario
        const generateToken = () => {
          return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
            expiresIn: 5400 // 90 minutos
          });
        };

        const token = generateToken();  // Generar el token

        // Responder con el token y la redirección
        res.status(200).json({ token, id_usuario: user.ID_USUARIO, redirect: '/pantalla_principal' });
      }
    );
  });
});


//Actualizar el estado de 2FA
app.post('/set2FAStatus', (req, res) => {
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
    const query = 'UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?';
    mysqlConnection.query(query, [enabled, userId], (err) => {
      if (err) {
        console.error('Error al actualizar el estado de 2FA:', err.message);
        return res.status(500).json({ message: 'Error interno del servidor' });
      }

      res.json({ message: 'Estado de 2FA actualizado correctamente' });
    });
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error al verificar el token' });
  }
});

//********** GET CODIGO 2FA ********
app.get('/get2FAStatus', (req, res) => {
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

    // Consultar el estado de 2FA en la base de datos
    const query = 'SELECT CODIGO_2FA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?';
    mysqlConnection.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Error al consultar el estado de 2FA:', err.message);
        return res.status(500).json({ message: 'Error interno del servidor' });
      }

      if (results.length > 0) {
        res.json({ enabled: results[0].CODIGO_2FA });
      } else {
        res.status(404).json({ message: 'Usuario no encontrado' });
      }
    });
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error al verificar el token' });
  }
});





//********** REGISTRO *********** 

const secretKey = 'clave_secreta';

// SERVIDOR DE CORREO MAILTRAP
const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "a576baf13dcf6f",
      pass: "0243f06cea3940"
    }
});

app.post('/register', async (req, res) => {
  const { NOMBRE_USUARIO, EMAIL, CONTRASEÑA } = req.body;

  if (!NOMBRE_USUARIO || !EMAIL || !CONTRASEÑA) {
      return res.status(400).json({ message: 'Todos los campos son requeridos' });
  }

  try {
      const hashedPassword = await bcrypt.hash(CONTRASEÑA, 8);

      mysqlConnection.query('SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL], (err, results) => {
          if (err) {
              console.error('Error al verificar el correo:', err);
              return res.status(500).json({ message: 'Error al registrar el usuario' });
          }

          if (results.length > 0) {
              return res.status(400).json({ message: 'Correo ya registrado' });
          }

          const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase();
          const cipher = crypto.createCipher('aes-128-cbc', secretKey);
          let encryptedVerificationCode = cipher.update(verificationCode, 'utf8', 'hex');
          encryptedVerificationCode += cipher.final('hex');

          const query = 'INSERT INTO TBL_MS_USUARIO (NOMBRE_USUARIO, EMAIL, CONTRASEÑA, CODIGO_VERIFICACION, ID_ROL, ID_ESTADO_USUARIO, CODIGO_2FA) VALUES (?, ?, ?, ?, ?, ?, ?)';
          mysqlConnection.query(query, [NOMBRE_USUARIO, EMAIL, hashedPassword, encryptedVerificationCode, 2, 5, 1], (err, results) => {
              if (err) {
                  console.error('Error al insertar usuario:', err);
                  return res.status(500).json({ message: 'Error al registrar el usuario' });
              }

              const userId = results.insertId; // Obtener el ID del usuario recién insertado

              // Insertar NOMBRE_USUARIO en la tabla TBL_PERSONAS
              const personaQuery = 'INSERT INTO TBL_PERSONAS (NOMBRE_PERSONA) VALUES (?)';
              mysqlConnection.query(personaQuery, [NOMBRE_USUARIO], (err, results) => {
                  if (err) {
                      console.error('Error al insertar nombre en TBL_PERSONAS:', err);
                      return res.status(500).json({ message: 'Error al registrar el usuario' });
                  }

                  const mailOptions = {
                      from: 'no-reply@yourdomain.com',
                      to: EMAIL,
                      subject: 'Código de Verificación',
                      text: `Tu código de verificación es: ${verificationCode}`
                  };

                  transporter.sendMail(mailOptions, (err, info) => {
                      if (err) {
                          console.error('Error al enviar el correo:', err);
                          return res.status(500).json({ message: 'Error al enviar el correo de verificación' });
                      }

                      // Generar el token
                      const token = jwt.sign({ id: userId }, SECRET_KEY, {
                          expiresIn: 1800 // 90 minutos
                      });

                      res.status(201).json({
                          token: token,
                          id_usuario: userId,
                          message: 'Usuario registrado exitosamente. Por favor verifica tu correo.'
                      });
                  });
              });
          });
      });
  } catch (err) {
      console.error('Error al cifrar la contraseña:', err);
      res.status(500).json({ message: 'Error al procesar el registro' });
  }
});


//******** Verificar registro ********
app.post('/verify', (req, res) => {
  const { EMAIL, CODIGO_VERIFICACION } = req.body;

  mysqlConnection.query('SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL], (err, results) => {
    if (err) {
      console.error('Error al verificar el código:', err);
      return res.status(500).json({ message: 'Error al verificar el código' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'Correo no encontrado' });
    }

    const user = results[0];

    if (user.INTENTOS_FALLIDOS >= 5) {
      mysqlConnection.query('DELETE FROM TBL_MS_USUARIO WHERE EMAIL = ?', [EMAIL], (err) => {
        if (err) {
          console.error('Error al eliminar el usuario:', err);
          return res.status(500).json({ message: 'Error al eliminar el usuario' });
        }

        return res.status(400).json({ message: 'Has alcanzado el límite de intentos de verificación.' });
      });
    } else {
      // Verifica si CODIGO_VERIFICACION es null
      if (user.CODIGO_VERIFICACION === null) {
        return res.status(400).json({ message: 'No hay un código de verificación disponible para este usuario' });
      }

      const decipher = crypto.createDecipher('aes-128-cbc', secretKey);
      let decryptedVerificationCode;

      try {
        decryptedVerificationCode = decipher.update(user.CODIGO_VERIFICACION, 'hex', 'utf8');
        decryptedVerificationCode += decipher.final('utf8');
      } catch (error) {
        console.error('Error al descifrar el código:', error);
        return res.status(500).json({ message: 'Error al procesar el código de verificación' });
      }

      if (CODIGO_VERIFICACION !== decryptedVerificationCode) {
        mysqlConnection.query('UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE EMAIL = ?', [EMAIL], (err) => {
          if (err) {
            console.error('Error al actualizar los intentos fallidos:', err);
            return res.status(500).json({ message: 'Error al actualizar los intentos fallidos' });
          }

          return res.status(400).json({ message: 'Código de verificación incorrecto' });
        });
      } else {
        const primerIngreso = moment().tz("America/Tegucigalpa").format('YYYY-MM-DD HH:mm:ss');

        mysqlConnection.query('SELECT VALOR FROM TBL_MS_PARAMETROS WHERE ID_PARAMETRO = 2', (err, parametroResults) => {
          if (err) {
            console.error('Error al obtener el parámetro:', err);
            return res.status(500).json({ message: 'Error al procesar el registro' });
          }

          const diasVencimiento = parseInt(parametroResults[0].VALOR, 10);
          const fechaVencimiento = moment().add(diasVencimiento, 'days').format('YYYY-MM-DD');

          mysqlConnection.query('UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL, PRIMER_INGRESO = ?, FECHA_VENCIMIENTO = ?, ID_ESTADO_USUARIO = 5, INTENTOS_FALLIDOS = 0 WHERE EMAIL = ?', [primerIngreso, fechaVencimiento, EMAIL], (err) => {
            if (err) {
              console.error('Error al actualizar el usuario:', err);
              return res.status(500).json({ message: 'Error al actualizar el usuario' });
            }

            res.status(200).json({ message: 'Correo verificado exitosamente' });
          });
        });
      }
    }
  });
});


//*********** RESTABLECER CONTRASENA    *********** 
app.post('/restablecer_contrasena', async (req, res) => {
    const { email } = req.body;
  
    mysqlConnection.query('SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?', [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Error al buscar el usuario' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
      }
  
      const tempPassword = crypto.randomBytes(4).toString('hex');
      const hashedTempPassword = bcrypt.hashSync(tempPassword, 10);
  
      // Eliminar cualquier entrada existente para el usuario en TBL_REINICIO_CONTRASEÑA
      mysqlConnection.query('DELETE FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?', [email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error al eliminar el token anterior' });
        }
  
        // Insertar la nueva entrada en TBL_REINICIO_CONTRASEÑA
        mysqlConnection.query(
          'INSERT INTO TBL_REINICIO_CONTRASEÑA (TOKEN, EMAIL) VALUES (?, ?)',
          [hashedTempPassword, email],
          (err, results) => {
            if (err) {
              return res.status(500).json({ message: 'Error al guardar el token' });
            }
  
            const mailOptions = {
              from: 'no-reply@yourdomain.com',
              to: email,
              subject: 'Restablecer contraseña',
              text: `Esta es tu contraseña de verificación para poder restablecer la contraseña: ${tempPassword}`
            };
  
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                return res.status(500).json({ message: 'Error al enviar el correo' });
              }
              return res.status(200).json({ message: 'Correo enviado con éxito' });
            });
          }
        );
      });
    });
  });
  
  
// ************ Ruta para verificar la contraseña temporal **********
app.post('/verificar_contrasena_temporal', (req, res) => {
  const { email, tempPassword } = req.body;

  mysqlConnection.query('SELECT * FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?', [email], (err, results) => {
    if (err) {
      console.error('Error al buscar el token', err);
      return res.status(500).json({ message: 'Error al buscar el token' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Token no encontrado' });
    }

    const token = results[0];
    const isMatch = bcrypt.compareSync(tempPassword, token.TOKEN);

    if (isMatch) {
      mysqlConnection.query('SELECT ID_USUARIO, CONTRASEÑA FROM TBL_MS_USUARIO WHERE EMAIL = ?', [email], (err, userResults) => {
        if (err) {
          console.error('Error al buscar el usuario', err);
          return res.status(500).json({ message: 'Error al buscar el usuario' });
        }

        if (userResults.length === 0) {
          return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const user = userResults[0];

        // Insertar en TBL_MS_HIST_CONTRASEÑA
        mysqlConnection.query('INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)', [user.ID_USUARIO, user.CONTRASEÑA], (err) => {
          if (err) {
            console.error('Error al insertar en el historial de contraseñas', err);
            return res.status(500).json({ message: 'Error al insertar en el historial de contraseñas' });
          }

          // Actualizar la contraseña, estado e intentos fallidos en TBL_MS_USUARIO
          const hashedTempPassword = bcrypt.hashSync(tempPassword, 10);
          mysqlConnection.query('UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ?, ID_ESTADO_USUARIO = 1, INTENTOS_FALLIDOS = 0 WHERE ID_USUARIO = ?', [hashedTempPassword, user.ID_USUARIO], (err) => {
            if (err) {
              console.error('Error al actualizar la contraseña, el estado y los intentos fallidos', err);
              return res.status(500).json({ message: 'Error al actualizar la contraseña, el estado y los intentos fallidos' });
            }

      // Generar token al inicio
      const generateToken = () => {
        return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
          expiresIn: 8400 // 90 minutos
        });
      };

      const token = generateToken();  // Generar el token

      res.status(200).json({ token, id_usuario: user.ID_USUARIO});
          });
        });
      });
    } else {
      return res.status(400).json({ message: 'Contraseña temporal incorrecta' });
    }
  });
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
  
      // Consultar la contraseña actual del usuario desde la base de datos
      mysqlConnection.query('SELECT CONTRASEÑA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [userId], async (err, results) => {
        if (err) {
          console.error('Error al buscar el usuario', err);
          return res.status(500).json({ message: 'Error al buscar el usuario' });
        }
  
        if (results.length === 0) {
          console.error('Usuario no encontrado');
          return res.status(404).json({ message: 'Usuario no encontrado' });
        }
  
        const contrasenaActual = results[0].CONTRASEÑA;
  
        // Verificar si la nueva contraseña es igual a la actual
        const isSamePassword = await bcrypt.compare(nueva, contrasenaActual);
        if (isSamePassword) {
          console.error('No puedes reutilizar la contraseña actual');
          return res.status(400).json({ message: 'No puedes reutilizar la contraseña actual' });
        }
  
        // Verificar si la contraseña actual proporcionada es correcta
        const isMatch = await bcrypt.compare(actual, contrasenaActual);
        if (!isMatch) {
          console.error('Contraseña actual incorrecta');
          return res.status(401).json({ message: 'Contraseña actual incorrecta' });
        }
  
        // Hashear la nueva contraseña
        const nuevaHashed = await bcrypt.hash(nueva, 10);
  
        // Insertar la contraseña actual en la tabla TBL_MS_HIST_CONTRASEÑA
        mysqlConnection.query('INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)', [userId, contrasenaActual], (err, results) => {
          if (err) {
            console.error('Error al insertar en el historial de contraseñas', err);
            return res.status(500).json({ message: 'Error al insertar en el historial de contraseñas' });
          }
  
          // Actualizar la nueva contraseña en la tabla TBL_MS_USUARIO
          mysqlConnection.query('UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ? WHERE ID_USUARIO = ?', [nuevaHashed, userId], (err, results) => {
            if (err) {
              console.error('Error al actualizar la contraseña', err);
              return res.status(500).json({ message: 'Error al actualizar la contraseña' });
            }
  
            res.status(200).json({ message: 'Contraseña actualizada correctamente' });
          });
        });
      });
    } catch (error) {
      console.error('Error al cambiar la contraseña:', error);
      res.status(500).json({ message: 'Error al cambiar la contraseña' });
    }
  });
  
  
  // ****** Ruta para cerrar sesión
app.post('/logout', verifyToken, (req, res) => {
  const token = req.headers['authorization'];

  // Si estás usando una lista negra de tokens, deberías agregar el token a la lista negra aquí.
  // Por ejemplo, puedes almacenar el token en una base de datos o en la memoria para su invalidación.

  return res.status(200).json({ message: 'Sesión cerrada exitosamente' });
});

// ************   Ruta para registrar una visita
app.post('/registrar_visitas', async (req, res) => {
  const { usuarioId, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, isRecurrentVisitor, FECHA_VENCIMIENTO } = req.body;

  try {
    // Obtener el NOMBRE_USUARIO usando el usuarioId
    mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
      if (err) {
        console.error('Error al obtener el nombre de usuario:', err);
        return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
      }

      if (!usuarioResults.length) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

      // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
      mysqlConnection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
        if (err) {
          console.error('Error al obtener el ID_PERSONA:', err);
          return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
        }

        if (!personaResults.length) {
          return res.status(404).json({ error: 'Persona no encontrada' });
        }

        const ID_PERSONA = personaResults[0].ID_PERSONA;

        // Obtener el valor del parámetro con ID_PARAMETRO = 3
        const parametroQuery = 'SELECT VALOR FROM TBL_MS_PARAMETROS WHERE ID_PARAMETRO = 3';
        mysqlConnection.query(parametroQuery, (err, parametroResults) => {
          if (err) {
            console.error('Error al obtener el parámetro:', err);
            return res.status(500).json({ message: 'Error al obtener el parámetro' });
          }
          if (parametroResults.length === 0) {
            return res.status(404).json({ message: 'Parámetro no encontrado' });
          }

          const horas = parametroResults[0].VALOR;
          const fechaActual = moment().tz('America/Tegucigalpa');
          const fechaCalculada = fechaActual.add(horas, 'hours').format('YYYY-MM-DD HH:mm:ss');
          const nuevaFechaActual = moment().tz('America/Tegucigalpa').format('YYYY-MM-DD HH:mm:ss'); // Create a new formatted date

          let insertQuery, insertParams;

          if (isRecurrentVisitor) {
            insertQuery = 'INSERT INTO TBL_VISITANTES_RECURRENTES (ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?, ?)';
            insertParams = [ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, nuevaFechaActual, FECHA_VENCIMIENTO];
          } else {
            insertQuery = 'INSERT INTO TBL_REGVISITAS (ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA) VALUES (?, ?, ?, ?, ?, ?)';
            insertParams = [ID_PERSONA, NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaCalculada];
          }

          mysqlConnection.query(insertQuery, insertParams, (err, results) => {
            if (err) {
              console.error('Error al registrar la visita:', err);
              return res.status(500).json({ message: 'Error al registrar la visita' });
            }

            // Insertar en la tabla TBL_BITACORA_VISITA
            const ID_VISITANTE = results.insertId; // Obtener el ID del visitante registrado

            let insertBitacoraQuery, insertBitacoraParams;

            if (isRecurrentVisitor) {
              insertBitacoraQuery = 'INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTE, NUM_PERSONA, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)';
              insertBitacoraParams = [ID_PERSONA, ID_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaActual.format('YYYY-MM-DD HH:mm:ss'), FECHA_VENCIMIENTO];
            } else {
              insertBitacoraQuery = 'INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTE, NUM_PERSONA, NUM_PLACA, FECHA_HORA) VALUES (?, ?, ?, ?, ?)';
              insertBitacoraParams = [ID_PERSONA, ID_VISITANTE, NUM_PERSONAS, NUM_PLACA, fechaCalculada];
            }

            mysqlConnection.query(insertBitacoraQuery, insertBitacoraParams, (err) => {
              if (err) {
                console.error('Error al registrar en la bitácora de visitas:', err);
                return res.status(500).json({ message: 'Error al registrar en la bitácora de visitas' });
              }

              // Obtener la información adicional del QR
              const personaInfoQuery = `
              SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
              FROM TBL_PERSONAS p
              LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
              LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
              WHERE p.ID_PERSONA = ?`;
            
            mysqlConnection.query(personaInfoQuery, [ID_PERSONA], (err, results) => {
              if (err) {
                console.error('Error al obtener la información del QR:', err);
                return res.status(500).json({ message: 'Error al obtener la información del QR' });
              }
            
              const personaInfo = results[0];
              let qrData;
            
              if (isRecurrentVisitor) {
                // Si es visitante recurrente, no incluir FECHA_HORA pero sí FECHA_VENCIMIENTO
                qrData = {
                  Residente: personaInfo.NOMBRE_PERSONA,
                  DNI_Residente: personaInfo.DNI_PERSONA,
                  Contacto: personaInfo.CONTACTO,
                  Condominio: personaInfo.ID_CONDOMINIO,  // Verifica que este campo esté presente
                  NOMBRE_VISITANTE,
                  DNI_VISITANTE,
                  NUM_PERSONAS,
                  NUM_PLACA,
                  FECHA_VENCIMIENTO: FECHA_VENCIMIENTO
                };
              } else {
                // Si no es visitante recurrente, incluir FECHA_HORA y no incluir FECHA_VENCIMIENTO
                qrData = {
                  Residente: personaInfo.NOMBRE_PERSONA,
                  DNI_Residente: personaInfo.DNI_PERSONA,
                  Contacto: personaInfo.CONTACTO,
                  Condominio: personaInfo.ID_CONDOMINIO,  // Verifica que este campo esté presente
                  NOMBRE_VISITANTE,
                  DNI_VISITANTE,
                  NUM_PERSONAS,
                  NUM_PLACA,
                  FECHA_HORA: fechaCalculada
                };
              }
                
                QRCode.toDataURL(JSON.stringify(qrData), (err, url) => {
                  if (err) {
                    console.error('Error al generar el código QR:', err);
                    return res.status(500).json({ message: 'Error al generar el código QR' });
                  }

                  const insertQRQuery = 'INSERT INTO TBL_QR (ID_VISITANTE, QR_CODE, FECHA_VENCIMIENTO) VALUES (?, ?, ?)';
                  mysqlConnection.query(insertQRQuery, [ID_VISITANTE, url, isRecurrentVisitor ? FECHA_VENCIMIENTO : fechaCalculada], (err) => {
                    if (err) {
                      console.error('Error al registrar el código QR:', err);
                      return res.status(500).json({ message: 'Error al registrar el código QR' });
                    }

                    res.status(201).json({
                      message: isRecurrentVisitor ? 'Visitante recurrente registrado exitosamente' : 'Visita registrada exitosamente',
                      qrCode: url
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});






app.post('/validateQR', (req, res) => {
  const { qrCode } = req.body;

  const searchQuery = 'SELECT * FROM TBL_QR WHERE QR_CODE = ?';
  mysqlConnection.query(searchQuery, [qrCode], (err, results) => {
    if (err) {
      console.error('Error al buscar el código QR:', err);
      return res.status(500).json({ message: 'Error al buscar el código QR' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Código QR no encontrado' });
    }

    const qrInfo = results[0];
    const fechaActual = moment().tz('America/Tegucigalpa').format('YYYY-MM-DD HH:mm:ss');

    if (fechaActual > qrInfo.FECHA_VENCIMIENTO) {
      return res.status(400).json({ message: 'Código QR expirado' });
    }

    res.status(200).json({ message: 'Código QR válido', qrInfo });
  });
});







// Crear un endpoint para obtener todos los anuncios
app.get('/anuncios_eventos', (req, res) => {
  const usuarioId = req.query.usuario_id; // Obtener el ID del usuario de la consulta
  const query = `
   SELECT ID_ANUNCIOS_EVENTOS, TITULO, DESCRIPCION, IMAGEN, FECHA_HORA 
   FROM TBL_ANUNCIOS_EVENTOS 
   WHERE ID_ESTADO_ANUNCIO_EVENTO = 1 
   AND ID_ANUNCIOS_EVENTOS NOT IN (
       SELECT ID_ANUNCIOS_EVENTOS FROM TBL_ANUNCIOS_OCULTOS WHERE ID_USUARIO = ?
   )
   ORDER BY FECHA_HORA DESC`; // Ordenar por la fecha y hora de forma descendente

  mysqlConnection.query(query, [usuarioId], (error, results) => {
      if (error) {
          console.error('Error al obtener los anuncios:', error);
          res.status(500).send('Error al obtener los anuncios');
      } else {
          res.status(200).json(results);
      }
  });
});

// Endpoint para ocultar un anuncio
app.post('/ocultar_anuncio', (req, res) => {
  const { usuarioId, anuncioId } = req.body;

  console.log('Datos recibidos:', req.body);
  
  const query = `
    INSERT INTO TBL_ANUNCIOS_OCULTOS (ID_USUARIO, ID_ANUNCIOS_EVENTOS) 
    VALUES (?, ?)`;

  mysqlConnection.query(query, [usuarioId, anuncioId], (error, results) => {
      if (error) {
          console.error('Error al ocultar el anuncio:', error);
          res.status(500).send('Error al ocultar el anuncio');
      } else {
          res.status(200).send('Anuncio ocultado exitosamente');
      }
  });
});

// Crear un endpoint para obtener los datos del perfil del usuario
app.get('/perfil', (req, res) => {
  const usuarioId = req.query.usuario_id;

  const query = `
    SELECT NOMBRE_USUARIO, EMAIL, ID_ROL 
    FROM TBL_MS_USUARIO 
    WHERE ID_USUARIO = ?`;

  mysqlConnection.query(query, [usuarioId], (error, results) => {
    if (error) {
      console.error('Error al obtener el perfil del usuario:', error);
      res.status(500).send('Error al obtener el perfil del usuario');
    } else {
      if (results.length > 0) {
        res.status(200).json(results[0]);
      } else {
        console.log(`Usuario con ID ${usuarioId} no encontrado`);
        res.status(404).send('Usuario no encontrado');
      }
    }
  });
});

//********** Consultar Reservaciones *********
app.get('/consultar_reservaciones', (req, res) => {
 const usuarioId = req.query.usuario_id;
 // const {usuarioId}= req.body;
// Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
  if (err) {
    console.error('Error al obtener el nombre de usuario:', err);
    return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
  }

  console.log('Resultados de usuario:', usuarioResults); // Agrega esto para depuración

  if (!usuarioResults.length) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

  // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
  mysqlConnection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
    if (err) {
      console.error('Error al obtener el ID_PERSONA:', err);
      return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
    }

    console.log('Resultados de persona:', personaResults); // Agrega esto para depuración

    if (!personaResults.length) {
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
            r.ID_PERSONA = ?
    `;

    mysqlConnection.query(query, [ID_PERSONA], (err, results) => {
      if (err) {
        console.error('Error al obtener las reservas:', err);
        return res.status(500).json({ error: 'Error al obtener las reservas' });
      }

      console.log('Resultados de reservaciones:', results); // Agrega esto para depuración

      res.json(results);
    });
  });
});

});

//********** Consultar Visitas *********
app.get('/consultar_visitas', (req, res) => {
  const usuarioId = req.query.usuario_id;

  // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
  mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
    if (err) {
      console.error('Error al obtener el nombre de usuario:', err);
      return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
    }

    if (!usuarioResults.length) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    mysqlConnection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
      if (err) {
        console.error('Error al obtener el ID_PERSONA:', err);
        return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
      }

      if (!personaResults.length) {
        return res.status(404).json({ error: 'Persona no encontrada' });
      }

      const ID_PERSONA = personaResults[0].ID_PERSONA;

      // Consultar los registros de visitas en TBL_REGVISITAS
      const queryRegVisitas = `
        SELECT NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, NULL AS FECHA_VENCIMIENTO, 'No recurrente' AS TIPO
        FROM TBL_REGVISITAS 
        WHERE ID_PERSONA = ?`;

      // Consultar los registros de visitas en TBL_VISITANTES_RECURRENTES
      const queryVisitantesRecurrentes = `
        SELECT NOMBRE_VISITANTE, DNI_VISITANTE, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO, 'Recurrente' AS TIPO
        FROM TBL_VISITANTES_RECURRENTES 
        WHERE ID_PERSONA = ?`;

      mysqlConnection.query(queryRegVisitas, [ID_PERSONA], (err, regVisitasResults) => {
        if (err) {
          console.error('Error al obtener registros de TBL_REGVISITAS:', err);
          return res.status(500).json({ error: 'Error al obtener registros de TBL_REGVISITAS' });
        }

        mysqlConnection.query(queryVisitantesRecurrentes, [ID_PERSONA], (err, visitantesRecurrentesResults) => {
          if (err) {
            console.error('Error al obtener registros de TBL_VISITANTES_RECURRENTES:', err);
            return res.status(500).json({ error: 'Error al obtener registros de TBL_VISITANTES_RECURRENTES' });
          }

          // Combinar los resultados de ambas consultas
          const resultados = [...regVisitasResults, ...visitantesRecurrentesResults];

          // Retornar los resultados a la aplicación Flutter
          res.json(resultados);
        });
      });
    });
  });
});

//********* Consultar familia ************
app.get('/consultar_familia', (req, res) => {
  const usuarioId = req.query.usuario_id;
  
  // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
  mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
    if (err) {
      console.error('Error al obtener el nombre de usuario:', err);
      return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
    }

    if (!usuarioResults.length) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA y el ID_CONDOMINIO de la tabla TBL_PERSONAS usando el nombreUsuario
    mysqlConnection.query('SELECT ID_PERSONA, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
      if (err) {
        console.error('Error al obtener el ID_PERSONA:', err);
        return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
      }

      if (!personaResults.length) {
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

      mysqlConnection.query(queryPersonas, [ID_CONDOMINIO], (err, personasResults) => {
        if (err) {
          console.error('Error al obtener personas del mismo condominio:', err);
          return res.status(500).json({ error: 'Error al obtener personas del mismo condominio' });
        }

        // Retornar los resultados a la aplicación Flutter
        res.json(personasResults);
      });
    });
  });
});

//********** Insertar Reserva *****
app.post('/nueva_reserva', (req, res) => {
  console.log('Datos recibidos:', req.body);
  const { usuarioId, nombreInstalacion, tipoEvento, horaFecha } = req.body;

    // Obtener el NOMBRE_USUARIO usando el usuarioId
    mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
      if (err) {
        console.error('Error al obtener el nombre de usuario:', err);
        return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
      }

      if (!usuarioResults.length) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

      // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
      mysqlConnection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
        if (err) {
          console.error('Error al obtener el ID_PERSONA:', err);
          return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
        }

        if (!personaResults.length) {
          return res.status(404).json({ error: 'Persona no encontrada' });
        }

        const ID_PERSONA = personaResults[0].ID_PERSONA;

    // Buscar ID_INSTALACION por nombre
    const findInstalacionQuery = 'SELECT ID_INSTALACION FROM TBL_INSTALACIONES WHERE NOMBRE_INSTALACION = ?';
    mysqlConnection.query(findInstalacionQuery, [nombreInstalacion], (err, instalacionResults) => {
      if (err) {
        console.error('Error al buscar instalación:', err);
        return res.status(500).json({ error: 'Error al buscar la instalación' });
      }

      if (instalacionResults.length === 0) {
        return res.status(404).json({ error: 'Instalación no encontrada' });
      }

      const ID_INSTALACION = instalacionResults[0].ID_INSTALACION;

      // Verificar si ya existe una reserva para esa fecha y hora en la misma instalación
      const checkReservaQuery = 'SELECT * FROM TBL_RESERVAS WHERE ID_INSTALACION = ? AND HORA_FECHA = ?';
      mysqlConnection.query(checkReservaQuery, [ID_INSTALACION, horaFecha], (err, reservaResults) => {
        if (err) {
          console.error('Error al verificar reserva existente:', err);
          return res.status(500).json({ error: 'Error al verificar la reserva' });
        }

        if (reservaResults.length > 0) {
          return res.status(400).json({ error: 'Horario ya reservado' });
        }

        // Insertar la reserva si no hay conflicto
        const insertReservaQuery = 'INSERT INTO TBL_RESERVAS (ID_PERSONA, ID_INSTALACION, ID_ESTADO_RESERVA, TIPO_EVENTO, HORA_FECHA) VALUES (?, ?, 3, ?, ?)';
        mysqlConnection.query(insertReservaQuery, [ID_PERSONA, ID_INSTALACION, tipoEvento, horaFecha], (err, insertResult) => {
          if (err) {
            console.error('Error al insertar la reserva:', err);
            return res.status(500).json({ error: 'Error al insertar la reserva' });
          }

          res.status(201).json({ message: 'Reserva creada exitosamente', reservaId: insertResult.insertId });
        });
      });
    });
  });
});
});


// ******* Tipos de Instalaciones *******
app.get('/instalaciones', (req, res) => {
  const query = 'SELECT NOMBRE_INSTALACION FROM TBL_INSTALACIONES';
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      console.error('Error al ejecutar la consulta:', err);
      return res.status(500).json({ error: 'Error al ejecutar la consulta' });
    }
    res.json(results);
  });
});


//Actualizar el estado de 2FA
app.post('/set2FAStatus', (req, res) => {
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
    const query = 'UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?';
    mysqlConnection.query(query, [enabled, userId], (err) => {
      if (err) {
        console.error('Error al actualizar el estado de 2FA:', err.message);
        return res.status(500).json({ message: 'Error interno del servidor' });
      }

      res.json({ message: 'Estado de 2FA actualizado correctamente' });
    });
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error al verificar el token' });
  }
});

//************** PERSONAS *************
app.get('/personas', (req, res) => {
  const query = 'SELECT DESCRIPCION FROM TBL_ESTADO_PERSONA';
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      console.error('Error al ejecutar la consulta:', err);
      return res.status(500).json({ error: 'Error al ejecutar la consulta' });
    }
    res.json(results);
  });
});

app.get('/contacto', (req, res) => {
  const query = 'SELECT DESCRIPCION FROM TBL_TIPO_CONTACTO';
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      console.error('Error al ejecutar la consulta:', err);
      return res.status(500).json({ error: 'Error al ejecutar la consulta' });
    }
    res.json(results);
  });
});

app.get('/parentesco', (req, res) => {
  const query = 'SELECT DESCRIPCION FROM TBL_PARENTESCOS';
  mysqlConnection.query(query, (err, results) => {
    if (err) {
      console.error('Error al ejecutar la consulta:', err);
      return res.status(500).json({ error: 'Error al ejecutar la consulta' });
    }
    res.json(results);
  });
});

//********* NUEVA PERSONA*********
app.post('/nueva_persona', (req, res) => {
  const { usuarioId, P_DNI, P_TIPO_CONTACTO, P_CONTACTO, P_PARENTESCO, P_CONDOMINIO } = req.body;

  console.log('Datos recibidos:', req.body);

  // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
  mysqlConnection.query('SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?', [usuarioId], (err, usuarioResults) => {
    if (err) {
      console.error('Error al obtener el nombre de usuario:', err);
      return res.status(500).json({ error: 'Error al obtener el nombre de usuario' });
    }

    if (!usuarioResults.length) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    mysqlConnection.query('SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?', [nombreUsuario], (err, personaResults) => {
      if (err) {
        console.error('Error al obtener el ID_PERSONA:', err);
        return res.status(500).json({ error: 'Error al obtener el ID_PERSONA' });
      }

      if (!personaResults.length) {
        return res.status(404).json({ error: 'Persona no encontrada' });
      }

      const ID_PERSONA = personaResults[0].ID_PERSONA;

      // Verificación si el condominio existe
      mysqlConnection.query('SELECT ID_CONDOMINIO FROM TBL_CONDOMINIOS WHERE DESCRIPCION = ?', [P_CONDOMINIO], (err, condominioResults) => {
        if (err) {
          console.error('Error al buscar condominio:', err);
          return res.status(500).json({ error: 'Error en la búsqueda de datos' });
        }

        if (!condominioResults.length) {
          return res.status(404).json({ error: 'Condominio no encontrado' });
        }

        const ID_CONDOMINIO = condominioResults[0].ID_CONDOMINIO;

        // Verificar si hay un administrador (ID_PADRE = 1) para este condominio
        mysqlConnection.query('SELECT COUNT(*) AS adminCount FROM TBL_PERSONAS WHERE ID_CONDOMINIO = ? AND ID_PADRE = 1', [ID_CONDOMINIO], (err, adminResults) => {
          if (err) {
            console.error('Error al verificar administrador:', err);
            return res.status(500).json({ error: 'Error al verificar administrador' });
          }

          const adminCount = adminResults[0].adminCount;
          const isAdminRequired = adminCount === 0; // Si no hay administrador, se debe insertar 1 en ID_PADRE

          // Consultar los IDs necesarios
          let queries = `
            SELECT ID_TIPO_CONTACTO FROM TBL_TIPO_CONTACTO WHERE DESCRIPCION = ?;
            SELECT ID_PARENTESCO FROM TBL_PARENTESCOS WHERE DESCRIPCION = ?;
          `;
          mysqlConnection.query(queries, [P_TIPO_CONTACTO, P_PARENTESCO], (err, results) => {
            if (err) {
              console.error('Error al buscar datos:', err);
              return res.status(500).json({ error: 'Error en la búsqueda de datos' });
            }

            const [tipoContactoResults, parentescoResults] = results;

            if (!tipoContactoResults.length || !parentescoResults.length) {
              return res.status(405).json({ error: 'Datos no encontrados' });
            }

            const ID_TIPO_CONTACTO = tipoContactoResults[0].ID_TIPO_CONTACTO;
            const ID_PARENTESCO = parentescoResults[0].ID_PARENTESCO;

            // Insertar contacto
            const insertContactoQuery = 'INSERT INTO TBL_CONTACTOS (ID_TIPO_CONTACTO, DESCRIPCION) VALUES (?, ?)';
            mysqlConnection.query(insertContactoQuery, [ID_TIPO_CONTACTO, P_CONTACTO], (err, contactoResults) => {
              if (err) {
                console.error('Error al insertar contacto:', err);
                return res.status(500).json({ error: 'Error al insertar el contacto' });
              }

              const ID_CONTACTO = contactoResults.insertId;

              // Construir consulta de actualización de persona
              let updatePersonaQuery;
              const queryParams = [P_DNI, ID_CONTACTO, 1, ID_PARENTESCO, ID_CONDOMINIO, ID_PERSONA];

              if (isAdminRequired) {
                updatePersonaQuery = `
                  UPDATE TBL_PERSONAS 
                  SET DNI_PERSONA = ?, ID_CONTACTO = ?, 
                  ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?, 
                  ID_CONDOMINIO = ?, ID_PADRE = 1
                  WHERE ID_PERSONA = ?
                `;
              } else {
                updatePersonaQuery = `
                  UPDATE TBL_PERSONAS 
                  SET DNI_PERSONA = ?, ID_CONTACTO = ?, 
                  ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?, 
                  ID_CONDOMINIO = ?, ID_PADRE = NULL
                  WHERE ID_PERSONA = ?
                `;
              }

              mysqlConnection.query(updatePersonaQuery, queryParams, (err, personaResults) => {
                if (err) {
                  console.error('Error al actualizar persona:', err);
                  return res.status(500).json({ error: 'Error al actualizar la persona' });
                }

                console.log('ID_PERSONA actualizado:', ID_PERSONA);

                // Enviar correo si es el primer administrador
                if (isAdminRequired) {
                  mysqlConnection.query('SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL = 1', (err, adminEmails) => {
                    if (err) {
                      console.error('Error al obtener correos de administradores:', err);
                      return res.status(500).json({ error: 'Error al obtener correos de administradores' });
                    }

                    const emailList = adminEmails.map(row => row.EMAIL);
                    const mailOptions = {
                      from: 'tuemail@dominio.com',
                      to: emailList,
                      subject: 'Nuevo Administrador de Condominio',
                      text: `Se ha registrado un nuevo administrador para el condominio:\n\nNombre: ${nombreUsuario}\nContacto: ${P_CONTACTO}\nCondominio: ${P_CONDOMINIO}`
                    };

                    transporter.sendMail(mailOptions, (err) => {
                      if (err) {
                        console.error('Error al enviar el correo:', err);
                        return res.status(500).json({ error: 'Error al enviar el correo' });
                      }
                      console.log('Correo enviado a:', emailList);
                    });
                  });
                }

                res.status(201).json({ success: true, message: 'Persona actualizada correctamente' });
              });
            });
          });
        });
      });
    });
  });
});

















//********** Actualizar lo PRIMER_INGRESO_COMPLETADO ********
app.put('/desactivarPersona', (req, res) => {
  const { ID_USUARIO } = req.body;

  if (!ID_USUARIO) {
    return res.status(400).json({ error: 'ID_USUARIO es requerido' });
  }

  const updateQuery = 'UPDATE TBL_MS_USUARIO SET PRIMER_INGRESO_COMPLETADO = 1 WHERE ID_USUARIO = ?';

  mysqlConnection.query(updateQuery, [ID_USUARIO], (err, result) => {
    if (err) {
      console.error('Error al actualizar PRIMER_INGRESO_COMPLETADO:', err);
      return res.status(500).json({ error: 'Error al actualizar PRIMER_INGRESO_COMPLETADO' });
    }

    if (result.affectedRows > 0) {
      res.status(200).json({ success: true, message: 'PRIMER_INGRESO_COMPLETADO actualizado correctamente' });
    } else {
      res.status(404).json({ error: 'No se encontró el usuario con el ID_USUARIO proporcionado' });
    }
  });
});
