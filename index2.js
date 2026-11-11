const nodemailer = require("nodemailer");
const mysql = require("mysql2/promise"); // Usa mysql2/promise
const express = require("express");
const bp = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const moment = require("moment-timezone");
const QRCode = require("qrcode");
const { exit } = require("process");
const pushService = require("./services/pushNotificationService");

const SECRET_KEY = "your_secret_key"; // Cambia esto por una clave secreta segura
const app = express();
app.use(["/registrar_solicitud_admin", "/responder_solicitud_admin"], bp.json({ limit: "12mb" }));
app.use(bp.json());

const QR_CIPHER_KEY = crypto.scryptSync("VillaLasAcacias2026@SecuritySecret", "saltAcaciasQr", 32);

function generarTokenSeguroQR(idVisitante, tipo) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", QR_CIPHER_KEY, iv);
  const payload = JSON.stringify({
    id: idVisitante,
    tipo: tipo,
    ts: Date.now()
  });
  let encrypted = cipher.update(payload, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `VLA_SEC_${iv.toString("hex")}_${encrypted}`;
}

function descifrarTokenSeguroQR(token) {
  if (!token || typeof token !== "string" || !token.startsWith("VLA_SEC_")) {
    return null;
  }
  const parts = token.split("_");
  if (parts.length !== 4) {
    return null;
  }
  const iv = Buffer.from(parts[2], "hex");
  const encryptedText = parts[3];
  const decipher = crypto.createDecipheriv("aes-256-cbc", QR_CIPHER_KEY, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

function parseFechaTegucigalpa(val) {
  if (!val) return null;
  if (typeof val === "string") {
    const cleanStr = val.replace("T", " ").replace("Z", "").split(".")[0];
    return moment.tz(cleanStr, "YYYY-MM-DD HH:mm:ss", "America/Tegucigalpa").isValid()
      ? moment.tz(cleanStr, "YYYY-MM-DD HH:mm:ss", "America/Tegucigalpa")
      : moment.tz(cleanStr, "America/Tegucigalpa");
  }
  return moment.tz(moment.utc(val).format("YYYY-MM-DD HH:mm:ss"), "America/Tegucigalpa");
}

const mysqlPool = mysql.createPool({
  host: "31.97.136.214",
  user: "u569522830_codemasters408",
  password: "Codem@sters123",
  database: "lasacacias",
  port: 3306,
  dateStrings: true,
  timezone: "-06:00",
  waitForConnections: true, // Espera si se supera el límite
  connectionLimit: 40, // ✅ MÁXIM0 conexiones simultáneas
  queueLimit: 0, // Sin límite en cola de espera
  connectTimeout: 60000, // Desconecta si está inactiva 60 segundos
});

// SERVIDOR DE CORREO
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,
  auth: {
    user: "villalasacacias@villalasacacias.com",
    pass: "Villalasacacias123@",
  },
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  let connection;

  try {
    connection = await mysqlPool.getConnection(); // Obtener conexión del pool

    const cleanUsername = (username || "").trim();
    const cleanPassword = (password || "").trim();

    // Consultar el usuario
    const [rows] = await connection.query(
      "SELECT * FROM TBL_MS_USUARIO WHERE LOWER(TRIM(EMAIL)) = LOWER(?) OR LOWER(TRIM(NOMBRE_USUARIO)) = LOWER(?)",
      [cleanUsername, cleanUsername]
    );

    if (rows.length === 0) {
      return res.status(401).send("Usuario no encontrado");
    }

    const user = rows[0];

    // Generar token al inicio
    const generateToken = () => {
      return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
        expiresIn: 8400, // 90 minutos
      });
    };

    const token = generateToken(); // Generar el token

    switch (user.ID_ESTADO_USUARIO) {
      case 2:
        return res.status(402).send("Usuario inactivo");
      case 3:
        return res.status(403).send("Usuario bloqueado");
      case 4:
        return res.status(404).send("Usuario Nuevo");
      case 5:
        return res.status(405).send("Usuario pendiente");
    }
    const passwordIsValid = bcrypt.compareSync(cleanPassword, user.CONTRASEÑA);

    if (!passwordIsValid) {
      connection = await mysqlPool.getConnection(); // Obtener nueva conexión del pool
      await connection.query(
        "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE ID_USUARIO = ?",
        [user.ID_USUARIO]
      );

      const [paramRows] = await connection.query(
        "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = ?",
        ["INTENTOS_FALLIDOS"]
      );

      const maxLoginAttempts = parseInt(paramRows[0].VALOR, 10);
      if (user.INTENTOS_FALLIDOS + 1 >= maxLoginAttempts + 1) {
        connection = await mysqlPool.getConnection(); // Obtener nueva conexión del pool
        await connection.query(
          "UPDATE TBL_MS_USUARIO SET ID_ESTADO_USUARIO = 3 WHERE ID_USUARIO = ?",
          [user.ID_USUARIO]
        );

        return res
          .status(403)
          .send("Usuario ha sido bloqueado por múltiples intentos fallidos");
      } else {
        return res.status(401).send("Contraseña incorrecta");
      }
    } else {
      await connection.query(
        `UPDATE TBL_MS_USUARIO 
                  SET INTENTOS_FALLIDOS = 0, 
                  PRIMER_INGRESO = IF(PRIMER_INGRESO IS NULL, CONVERT_TZ(NOW(), @@session.time_zone, '-06:00'), PRIMER_INGRESO) 
                  WHERE ID_USUARIO = ?`,
        [user.ID_USUARIO]
      );
      if (user.CODIGO_2FA === 1) {
        // Generar y enviar código de verificación
        const verificationCode = crypto
          .randomBytes(3)
          .toString("hex")
          .toUpperCase(); // Código de 6 dígitos en mayúsculas

        await connection.query(
          "UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = ? WHERE ID_USUARIO = ?",
          [verificationCode, user.ID_USUARIO]
        );

        const mailOptions = {
          from: "villalasacacias@villalasacacias.com",
          to: user.EMAIL,
          subject: "Código de Verificación 2FA",
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
                      `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.log(error);
            return res
              .status(500)
              .send("Error al enviar el código de verificación");
          }
          // Enviar respuesta con el token y redirección para la verificación de código
          res.status(200).json({
            token,
            id_usuario: user.ID_USUARIO,
            redirect: "/validar_codigo_2fa",
          });
        });
      } else {
        // Si no se requiere 2FA, simplemente retorna el token y redirige
        res.status(200).json({
          token,
          id_usuario: user.ID_USUARIO,
          redirect: "/pantalla_principal",
        });
      }
    }
  } catch (err) {
    console.error("Error en /login:", err);
    res.status(500).send("Error interno del servidor");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
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

app.get("/protected", verifyToken, (req, res) => {
  res.status(200).send("Access granted");
});

//*************** Verificacion de 2FA *********
app.post("/validar_codigo_2fa", async (req, res) => {
  const { ID_USUARIO, CODIGO_VERIFICACION } = req.body;
  let connection;

  try {
    connection = await mysqlPool.getConnection();

    const [results] = await connection.query(
      "SELECT * FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [ID_USUARIO]
    );

    if (results.length === 0) {
      return res.status(400).json({ message: "Usuario no encontrado" });
    }

    const user = results[0];

    if (user.CODIGO_VERIFICACION !== CODIGO_VERIFICACION) {
      return res
        .status(400)
        .json({ message: "Código de verificación incorrecto" });
    }

    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL WHERE ID_USUARIO = ?",
      [ID_USUARIO]
    );

    const generateToken = () => {
      return jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
        expiresIn: 5400, // 90 minutos
      });
    };

    const token = generateToken(); // Generar el token

    res.status(200).json({
      token,
      id_usuario: user.ID_USUARIO,
      redirect: "/pantalla_principal",
    });
  } catch (err) {
    console.error("Error al verificar el código:", err);
    res.status(500).json({ message: "Error al verificar el código" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//Actualizar el estado de 2FA
app.post("/set2FAStatus", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error("Token no proporcionado");
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const { enabled } = req.body;
    if (typeof enabled !== "number" || (enabled !== 0 && enabled !== 1)) {
      return res.status(400).json({ message: "Valor inválido para 2FA" });
    }

    connection = await mysqlPool.getConnection();
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?",
      [enabled, userId]
    );

    res.json({ message: "Estado de 2FA actualizado correctamente" });
  } catch (error) {
    console.error("Error al verificar el token:", error);
    res.status(500).json({ message: "Error al verificar el token" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** GET CODIGO 2FA ********
app.get("/get2FAStatus", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error("Token no proporcionado");
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT CODIGO_2FA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [userId]
    );

    if (results.length > 0) {
      res.json({ enabled: results[0].CODIGO_2FA });
    } else {
      res.status(404).json({ message: "Usuario no encontrado" });
    }
  } catch (error) {
    console.error("Error al verificar el token:", error);
    res.status(500).json({ message: "Error al verificar el token" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** REGISTRO ***********

const secretKey = crypto.randomBytes(32); // Clave secreta de 256 bits
const iv = Buffer.alloc(16, 0); // IV de 16 bytes

// Cifrado
function encrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", secretKey, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

// Descifrado
function decrypt(encryptedText) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", secretKey, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

app.post("/register", async (req, res) => {
  const { NOMBRE_USUARIO, EMAIL, CONTRASEÑA } = req.body;

  console.log("Iniciando proceso de registro.");

  if (!NOMBRE_USUARIO || !EMAIL || !CONTRASEÑA) {
    console.error("Faltan campos requeridos:", {
      NOMBRE_USUARIO,
      EMAIL,
      CONTRASEÑA,
    });
    return res.status(400).json({ message: "Todos los campos son requeridos" });
  }
  let connection;
  try {
    console.log("Cifrando contraseña.");
    const hashedPassword = await bcrypt.hash(CONTRASEÑA, 8);
    connection = await mysqlPool.getConnection(); // Obtener conexión del pool
    console.log("Conexión a la base de datos establecida.");

    // Verificar si el nombre de usuario ya existe
    const [existingUser] = await connection.query(
      "SELECT NOMBRE_USUARIO, PRIMER_INGRESO_COMPLETADO FROM TBL_MS_USUARIO WHERE NOMBRE_USUARIO = ?",
      [NOMBRE_USUARIO]
    );

    if (existingUser.length > 0) {
      const usuarioExistente = existingUser[0];

      if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 1) {
        console.error("Persona ya registrada y primer ingreso completado.");
        return res
          .status(400)
          .json({ message: "Nombre de persona ya registrado" });
      }
    }

    // Verificar si el correo ya está registrado y el estado de PRIMER_INGRESO_COMPLETADO
    const [results] = await connection.query(
      "SELECT NOMBRE_USUARIO, PRIMER_INGRESO_COMPLETADO, ID_USUARIO FROM TBL_MS_USUARIO WHERE EMAIL = ?",
      [EMAIL]
    );

    if (results.length > 0) {
      console.log(
        "Correo ya registrado. Verificando estado de primer ingreso."
      );
      const usuarioExistente = results[0];

      if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 1) {
        console.error("El usuario ya ha completado el primer ingreso.");
        return res.status(400).json({ message: "Correo ya registrado" });
      }
      if (usuarioExistente.PRIMER_INGRESO_COMPLETADO === 0) {
        console.log("Actualizando datos del usuario existente 0000.");
        const verificationCode = crypto
          .randomBytes(3)
          .toString("hex")
          .toUpperCase();
        const cipher = crypto.createCipheriv(
          "aes-256-cbc",
          Buffer.from(secretKey, "hex"),
          Buffer.alloc(16, 0)
        );
        let encryptedVerificationCode = cipher.update(
          verificationCode,
          "utf8",
          "hex"
        );
        encryptedVerificationCode += cipher.final("hex");

        // Actualizar datos en TBL_MS_USUARIO
        const updateQuery =
          "UPDATE TBL_MS_USUARIO SET NOMBRE_USUARIO = ?, CONTRASEÑA = ?, CODIGO_VERIFICACION = ?, ID_ROL = ?, ID_ESTADO_USUARIO = ?, CODIGO_2FA = ? WHERE EMAIL = ?";
        await connection.query(updateQuery, [
          NOMBRE_USUARIO,
          hashedPassword,
          encryptedVerificationCode,
          2,
          5,
          0,
          EMAIL,
        ]);
        console.log("Datos del usuario actualizados en TBL_MS_USUARIO.");

        // Capturar el nombre de usuario asociado con el correo
        const existingName = usuarioExistente.NOMBRE_USUARIO;

        // Actualizar el NOMBRE_PERSONA en TBL_PERSONAS
        const updatePersonaQuery =
          "UPDATE TBL_PERSONAS SET NOMBRE_PERSONA = ? WHERE NOMBRE_PERSONA = ?";
        await connection.query(updatePersonaQuery, [
          NOMBRE_USUARIO,
          existingName,
        ]);
        console.log("Nombre de persona actualizado en TBL_PERSONAS.");

        // Configurar y enviar el correo electrónico
        const mailOptions = {
          from: "villalasacacias@villalasacacias.com",
          to: EMAIL,
          subject: "Código de Verificación",
          html: `
            <p>Estimado/a,</p>
            <p>Hemos recibido una solicitud para verificar tu cuenta en nuestro sistema. Para completar el proceso, por favor utiliza el siguiente código de verificación:</p>
            <p style="font-size: 24px; font-weight: bold;">${verificationCode}</p>
            <p>Este código es válido por un tiempo limitado, por lo que te recomendamos usarlo lo antes posible.</p>
            <p>Si no solicitaste esta verificación, por favor ignora este mensaje.</p>
            <p>Gracias por confiar en nosotros.</p>
            <p>Atentamente,</p>
            <p>El equipo de soporte de Villas Las Acacias</p>
          `,
        };

        transporter.sendMail(mailOptions, (err) => {
          if (err) {
            console.error("Error al enviar el correo:", err);
            return res
              .status(500)
              .json({ message: "Error al enviar el correo de verificación" });
          }

          console.log("Correo de verificación enviado con éxito.");
          // Generar el token
          const token = jwt.sign(
            { id: usuarioExistente.ID_USUARIO },
            SECRET_KEY,
            {
              expiresIn: 1800, // 30 minutos
            }
          );

          // Enviar respuesta al cliente
          res.status(201).json({
            token: token,
            id_usuario: usuarioExistente.ID_USUARIO,
            message:
              "Usuario registrado exitosamente. Por favor verifica tu correo.",
          });
        });

        return;
      }
    }

    // Si el correo no existe, proceder con el registro normal
    console.log(
      "Correo no registrado previamente. Procediendo con el registro."
    );
    const verificationCode = crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();
    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(secretKey, "hex"),
      Buffer.alloc(16, 0)
    );
    let encryptedVerificationCode = cipher.update(
      verificationCode,
      "utf8",
      "hex"
    );
    encryptedVerificationCode += cipher.final("hex");

    const query =
      "INSERT INTO TBL_MS_USUARIO (NOMBRE_USUARIO, EMAIL, CONTRASEÑA, CODIGO_VERIFICACION, ID_ROL, ID_ESTADO_USUARIO, CODIGO_2FA) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const [insertResults] = await connection.query(query, [
      NOMBRE_USUARIO,
      EMAIL,
      hashedPassword,
      encryptedVerificationCode,
      2,
      5,
      0,
    ]);
    const userId = insertResults.insertId; // Obtener el ID del usuario recién insertado
    console.log("Usuario registrado en TBL_MS_USUARIO con ID:", userId);

    // Insertar NOMBRE_USUARIO en la tabla TBL_PERSONAS
    const personaQuery = "INSERT INTO TBL_PERSONAS (NOMBRE_PERSONA) VALUES (?)";
    await connection.query(personaQuery, [NOMBRE_USUARIO]);
    console.log("Nombre de usuario insertado en TBL_PERSONAS.");

    // Configurar y enviar el correo electrónico
    const mailOptions = {
      from: "villalasacacias@villalasacacias.com",
      to: EMAIL,
      subject: "Código de Verificación",
      html: `
        <p>Estimado/a,</p>
        <p>Hemos recibido una solicitud para verificar tu cuenta en nuestro sistema. Para completar el proceso, por favor utiliza el siguiente código de verificación:</p>
        <p style="font-size: 24px; font-weight: bold;">${verificationCode}</p>
        <p>Este código es válido por un tiempo limitado, por lo que te recomendamos usarlo lo antes posible.</p>
        <p>Si no solicitaste esta verificación, por favor ignora este mensaje.</p>
        <p>Gracias por confiar en nosotros.</p>
        <p>Atentamente,</p>
        <p>El equipo de soporte de Villas Las Acacias</p>
      `,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error("Error al enviar el correo:", err);
        return res
          .status(500)
          .json({ message: "Error al enviar el correo de verificación" });
      }

      console.log("Correo de verificación enviado con éxito.");
      // Generar el token
      const token = jwt.sign({ id: userId }, SECRET_KEY, {
        expiresIn: 1800, // 30 minutos
      });

      // Enviar respuesta al cliente
      res.status(201).json({
        token: token,
        id_usuario: userId,
        message:
          "Usuario registrado exitosamente. Por favor verifica tu correo.",
      });
    });
  } catch (err) {
    console.error("Error al procesar el registro:", err);
    res.status(500).json({ message: "Error al procesar el registro" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//******** Verificar registro ********
app.post("/verify", async (req, res) => {
  const { EMAIL, CODIGO_VERIFICACION } = req.body;

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [results] = await connection.query(
      "SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?",
      [EMAIL]
    );

    if (results.length === 0) {
      return res.status(400).json({ message: "Correo no encontrado" });
    }

    const user = results[0];

    if (user.INTENTOS_FALLIDOS >= 5) {
      await connection.query("DELETE FROM TBL_MS_USUARIO WHERE EMAIL = ?", [
        EMAIL,
      ]);
      return res.status(400).json({
        message: "Has alcanzado el límite de intentos de verificación.",
      });
    }

    if (user.CODIGO_VERIFICACION === null) {
      return res.status(400).json({
        message:
          "No hay un código de verificación disponible para este usuario",
      });
    }

    // Configurar el descifrado usando los mismos parámetros que en el cifrado
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(secretKey, "hex"),
      Buffer.alloc(16, 0)
    );
    let decryptedVerificationCode;

    try {
      decryptedVerificationCode = decipher.update(
        user.CODIGO_VERIFICACION,
        "hex",
        "utf8"
      );
      decryptedVerificationCode += decipher.final("utf8");
    } catch (error) {
      console.error("Error al descifrar el código:", error);
      return res
        .status(500)
        .json({ message: "Error al procesar el código de verificación" });
    }

    if (CODIGO_VERIFICACION !== decryptedVerificationCode) {
      await connection.query(
        "UPDATE TBL_MS_USUARIO SET INTENTOS_FALLIDOS = INTENTOS_FALLIDOS + 1 WHERE EMAIL = ?",
        [EMAIL]
      );
      return res
        .status(400)
        .json({ message: "Código de verificación incorrecto" });
    }

    const primerIngreso = moment()
      .tz("America/Tegucigalpa")
      .format("YYYY-MM-DD HH:mm:ss");

    const [parametroResults] = await connection.query(
      "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE ID_PARAMETRO = 2"
    );
    const diasVencimiento = parseInt(parametroResults[0].VALOR, 10);
    const fechaVencimiento = moment()
      .add(diasVencimiento, "days")
      .format("YYYY-MM-DD");

    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CODIGO_VERIFICACION = NULL, PRIMER_INGRESO = ?, FECHA_VENCIMIENTO = ?, ID_ESTADO_USUARIO = 5, INTENTOS_FALLIDOS = 0 WHERE EMAIL = ?",
      [primerIngreso, fechaVencimiento, EMAIL]
    );

    try {
      const [padreRows] = await connection.query(
        `SELECT uPadre.ID_USUARIO 
         FROM TBL_MS_USUARIO uHijo
         JOIN TBL_PERSONAS pHijo ON uHijo.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = pHijo.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
         JOIN TBL_PERSONAS pPadre ON pHijo.ID_CONDOMINIO = pPadre.ID_CONDOMINIO AND pPadre.ID_PADRE = 1
         JOIN TBL_MS_USUARIO uPadre ON uPadre.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = pPadre.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
         WHERE uHijo.EMAIL = ?`,
        [EMAIL]
      );
      for (const p of padreRows) {
        pushService.notificarUsuario(mysqlPool, p.ID_USUARIO, {
          titulo: "Nuevo residente pendiente",
          mensaje: `${user.NOMBRE_USUARIO} ha solicitado acceso y requiere tu aprobación.`,
          tipo: "FAMILIA",
          data: { ruta: "/solicitudes_residentes" },
        }).catch(() => {});
      }
    } catch (eNotif) {
      console.error("Error al notificar al padre residente:", eNotif);
    }

    res.status(200).json({ message: "Correo verificado exitosamente" });
  } catch (error) {
    console.error("Error al procesar la verificación:", error);
    res.status(500).json({ message: "Error al procesar la verificación" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//*********** RESTABLECER CONTRASENA    ***********
app.post("/restablecer_contrasena", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ message: "El campo de correo electrónico es requerido." });
  }
  let connection;
  try {
    connection = await mysqlPool.getConnection(); // Obtener conexión del pool

    // Verificar si el usuario existe
    const [userResults] = await connection.query(
      "SELECT * FROM TBL_MS_USUARIO WHERE EMAIL = ?",
      [email]
    );

    if (userResults.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const estadoUsuario = userResults[0].ID_ESTADO_USUARIO;

    if ([2, 4, 5].includes(estadoUsuario)) {
      return res.status(405).json({ message: "Estado de usuario denegado." });
    }

    const tempPassword = crypto.randomBytes(4).toString("hex");
    const hashedTempPassword = await bcrypt.hash(tempPassword, 10);

    // Eliminar cualquier entrada existente para el usuario en TBL_REINICIO_CONTRASEÑA
    await connection.query(
      "DELETE FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?",
      [email]
    );

    // Insertar la nueva entrada en TBL_REINICIO_CONTRASEÑA
    await connection.query(
      "INSERT INTO TBL_REINICIO_CONTRASEÑA (TOKEN, EMAIL) VALUES (?, ?)",
      [hashedTempPassword, email]
    );

    // Configurar y enviar el correo electrónico
    const mailOptions = {
      from: "villalasacacias@villalasacacias.com",
      to: email,
      subject: "Restablecimiento de Contraseña",
      html: `
                <p>Estimado/a usuario/a,</p>
                <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta. Para proceder, por favor utiliza la siguiente contraseña temporal:</p>
                <p style="font-size: 24px; font-weight: bold;">${tempPassword}</p>
                <p>Te recomendamos que inicies sesión con esta contraseña temporal y la cambies de inmediato para proteger tu cuenta.</p>
                <p>Si no solicitaste este restablecimiento, te recomendamos que ignores este correo y te pongas en contacto con nuestro equipo de administración de Villas Las Acacias inmediatamente.</p>
                <p>Gracias por tu atención.</p>
                <p>Atentamente,</p>
                <p>El equipo de administración de Villas Las Acacias</p>
            `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: "Error al enviar el correo" });
      }
      return res.status(200).json({ message: "Correo enviado con éxito" });
    });
  } catch (err) {
    console.error("Error al procesar el restablecimiento de contraseña:", err);
    res.status(500).json({ message: "Error al procesar la solicitud" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

app.post("/verificar_contrasena_temporal", async (req, res) => {
  const { email, tempPassword } = req.body;

  if (!email || !tempPassword) {
    return res.status(400).json({
      message: "El correo electrónico y la contraseña temporal son requeridos",
    });
  }
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // Verificar el token
    const [tokenResults] = await connection.query(
      "SELECT * FROM TBL_REINICIO_CONTRASEÑA WHERE EMAIL = ?",
      [email]
    );

    if (tokenResults.length === 0) {
      return res.status(404).json({ message: "Token no encontrado" });
    }

    let token = tokenResults[0]; // Cambiado const por let
    const isMatch = await bcrypt.compare(tempPassword, token.TOKEN);

    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Contraseña temporal incorrecta" });
    }

    // Obtener los datos del usuario
    const [userResults] = await connection.query(
      "SELECT ID_USUARIO, CONTRASEÑA FROM TBL_MS_USUARIO WHERE EMAIL = ?",
      [email]
    );

    if (userResults.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userResults[0];

    // Insertar en TBL_MS_HIST_CONTRASEÑA
    await connection.query(
      "INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)",
      [user.ID_USUARIO, user.CONTRASEÑA]
    );

    // Actualizar la contraseña, estado e intentos fallidos en TBL_MS_USUARIO
    const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ?, ID_ESTADO_USUARIO = 1, INTENTOS_FALLIDOS = 0 WHERE ID_USUARIO = ?",
      [hashedTempPassword, user.ID_USUARIO]
    );

    // Generar el token
    token = jwt.sign({ id: user.ID_USUARIO }, SECRET_KEY, {
      expiresIn: 8400, // 90 minutos
    });

    res.status(200).json({ token, id_usuario: user.ID_USUARIO });
  } catch (error) {
    console.error(
      "Error al procesar la verificación de la contraseña temporal:",
      error
    );
    res.status(500).json({
      message: "Error al procesar la verificación de la contraseña temporal",
    });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// ************  Ruta para actualizar la contraseña   **********
app.post("/cambiar_contrasena", async (req, res) => {
  const { actual, nueva } = req.body;

  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error("Token no proporcionado");
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // Verificar y decodificar el token
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    connection = await mysqlPool.getConnection();

    // Consultar la contraseña actual del usuario desde la base de datos
    const [userResults] = await connection.query(
      "SELECT CONTRASEÑA FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [userId]
    );

    if (userResults.length === 0) {
      console.error("Usuario no encontrado");
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const contrasenaActual = userResults[0].CONTRASEÑA;

    // Verificar si la nueva contraseña es igual a la actual
    const isSamePassword = await bcrypt.compare(nueva, contrasenaActual);
    if (isSamePassword) {
      console.error("No puedes reutilizar la contraseña actual");
      return res
        .status(400)
        .json({ message: "No puedes reutilizar la contraseña actual" });
    }

    // Verificar si la contraseña actual proporcionada es correcta
    const isMatch = await bcrypt.compare(actual, contrasenaActual);
    if (!isMatch) {
      console.error("Contraseña actual incorrecta");
      return res.status(401).json({ message: "Contraseña actual incorrecta" });
    }
    // Hashear la nueva contraseña
    const nuevaHashed = await bcrypt.hash(nueva, 10);
    // Insertar la contraseña actual en la tabla TBL_MS_HIST_CONTRASEÑA
    await connection.query(
      "INSERT INTO TBL_MS_HIST_CONTRASEÑA (ID_USUARIO, CONTRASEÑA) VALUES (?, ?)",
      [userId, contrasenaActual]
    );
    // Actualizar la nueva contraseña en la tabla TBL_MS_USUARIO
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CONTRASEÑA = ? WHERE ID_USUARIO = ?",
      [nuevaHashed, userId]
    );

    res.status(200).json({ message: "Contraseña actualizada correctamente" });
  } catch (error) {
    console.error("Error al cambiar la contraseña:", error);
    res.status(500).json({ message: "Error al cambiar la contraseña" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// ************   Ruta para registrar una visita
app.post("/registrar_visitas", async (req, res) => {
  const {
    usuarioId,
    NOMBRE_VISITANTE,
    NACIONALIDAD,
    DNI_VISITANTE,
    CARNET_EXTRANJERO,
    NUM_PERSONAS,
    NUM_PLACA,
    isRecurrentVisitor,
    FECHA_VENCIMIENTO,
  } = req.body;
  let connection;

  // Validar que se tenga DNI o Carnet de Extranjero según la nacionalidad
  const esHondurena =
    NACIONALIDAD && NACIONALIDAD.toLowerCase().includes("hondureña");

  if (esHondurena && !DNI_VISITANTE) {
    return res
      .status(400)
      .json({ error: "El DNI es requerido para nacionalidad hondureña" });
  }

  if (!esHondurena && !CARNET_EXTRANJERO) {
    return res.status(400).json({
      error:
        "El Carnet de Extranjero es requerido para nacionalidad extranjera",
    });
  }

  try {
    connection = await mysqlPool.getConnection();

    // ********* NUEVA VALIDACIÓN: Validar DNI hondureño *********
    if (esHondurena && DNI_VISITANTE) {
      // Validar que el DNI tenga al menos 4 dígitos
      if (DNI_VISITANTE.length < 4) {
        return res.status(400).json({
          error: "El número de identidad debe tener al menos 4 dígitos",
        });
      }

      // Obtener los primeros 4 dígitos del DNI
      const codigoDNI = DNI_VISITANTE.substring(0, 4);
      // Validar el código en la tabla TBL_CODIGO_DNI
      const [codigoResults] = await connection.query(
        "SELECT COUNT(*) as count FROM TBL_CODIGO_DNI WHERE CODIGO = ?",
        [codigoDNI]
      );

      if (codigoResults[0].count === 0) {
        return res.status(400).json({
          error:
            "El número de identidad ingresado no corresponde a un código válido. Por favor, verifique su DNI.",
        });
      }
    }

    // ********* OBTENER ID_NACIONALIDAD *********
    let ID_NACIONALIDAD = null;
    if (NACIONALIDAD) {
      const [nacionalidadResults] = await connection.query(
        "SELECT ID_NACIONALIDAD FROM TBL_NACIONALIDADES WHERE NOMBRE_NACIONALIDAD = ?",
        [NACIONALIDAD]
      );

      if (nacionalidadResults.length > 0) {
        ID_NACIONALIDAD = nacionalidadResults[0].ID_NACIONALIDAD;
      } else {
        return res.status(400).json({ error: "Nacionalidad no encontrada" });
      }
    }

    // Obtener el NOMBRE_USUARIO usando el usuarioId
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;
    
    // Obtener el valor del parámetro con ID_PARAMETRO = QR_VENCIMIENTO
    const [parametroResults] = await connection.query(
      'SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = "QR_VENCIMIENTO"'
    );

    if (parametroResults.length === 0) {
      return res.status(404).json({ message: "Parámetro no encontrado" });
    }

    const horas = parametroResults[0].VALOR;
    const fechaActual = moment().tz("America/Tegucigalpa");
    const fechaCalculada = fechaActual
      .add(horas, "hours")
      .format("YYYY-MM-DD HH:mm:ss");

    // Convertir FECHA_VENCIMIENTO al formato 'YYYY-MM-DD HH:mm:ss'
    const fechaVencimiento = moment(
      FECHA_VENCIMIENTO,
      "DD-MM-YYYY HH:mm"
    ).format("YYYY-MM-DD HH:mm:ss");
   
    const numPersonasVal = NUM_PERSONAS ? parseInt(NUM_PERSONAS) : 1;
    let insertQuery, insertParams;

    if (isRecurrentVisitor) {
      const fechaActual = moment().tz("America/Tegucigalpa");
      insertQuery =
        "INSERT INTO TBL_VISITANTES_RECURRENTES (ID_PERSONA, NOMBRE_VISITANTE, ID_NACIONALIDAD, DNI_VISITANTE, NUM_CARNET_EXTRANJERO, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
      insertParams = [
        ID_PERSONA,
        NOMBRE_VISITANTE,
        ID_NACIONALIDAD,
        DNI_VISITANTE,
        CARNET_EXTRANJERO,
        numPersonasVal,
        NUM_PLACA,
        fechaActual.format("YYYY-MM-DD HH:mm:ss"),
        fechaVencimiento,
      ];
    } else {
      const fechaActual = moment().tz("America/Tegucigalpa");
      insertQuery =
        "INSERT INTO TBL_REGVISITAS (ID_PERSONA, NOMBRE_VISITANTE, ID_NACIONALIDAD, DNI_VISITANTE, NUM_CARNET_EXTRANJERO, NUM_PERSONAS, NUM_PLACA, FECHA_HORA) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
      insertParams = [
        ID_PERSONA,
        NOMBRE_VISITANTE,
        ID_NACIONALIDAD,
        DNI_VISITANTE,
        CARNET_EXTRANJERO,
        numPersonasVal,
        NUM_PLACA,
        fechaActual.format("YYYY-MM-DD HH:mm:ss"),
      ];
    }

    const [result] = await connection.query(insertQuery, insertParams);

    // Insertar en la tabla TBL_BITACORA_VISITA
    const ID_VISITANTE = result.insertId; // Obtener el ID del visitante registrado

    let insertBitacoraQuery, insertBitacoraParams;

    if (isRecurrentVisitor) {
      const fechaActual = moment().tz("America/Tegucigalpa");
      insertBitacoraQuery =
        "INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTES_RECURRENTES, NUM_PERSONA, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)";
      insertBitacoraParams = [
        ID_PERSONA,
        ID_VISITANTE,
        numPersonasVal,
        NUM_PLACA,
        fechaActual.format("YYYY-MM-DD HH:mm:ss"),
        fechaVencimiento,
      ];
    } else {
      const fechaActual = moment().tz("America/Tegucigalpa");
      insertBitacoraQuery =
        "INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTE, NUM_PERSONA, NUM_PLACA, FECHA_HORA,FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)";
      insertBitacoraParams = [
        ID_PERSONA,
        ID_VISITANTE,
        numPersonasVal,
        NUM_PLACA,
        fechaActual.format("YYYY-MM-DD HH:mm:ss"),
        fechaCalculada,
      ];
    }

    await connection.query(insertBitacoraQuery, insertBitacoraParams);

    // Obtener la información adicional del QR
    const [personaInfoResults] = await connection.query(
      `
      SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, p.NUM_CARNET_EXTRANJERO, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
      FROM TBL_PERSONAS p
      LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
      LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
      WHERE p.ID_PERSONA = ?`,
      [ID_PERSONA]
    );

    if (personaInfoResults.length === 0) {
      return res
        .status(404)
        .json({ message: "Información del QR no encontrada" });
    }

    const personaInfo = personaInfoResults[0];
    let qrData;

    if (isRecurrentVisitor) {
      qrData = {
        Residente: personaInfo.NOMBRE_PERSONA,
        DNI_Residente: personaInfo.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: personaInfo.NUM_CARNET_EXTRANJERO,
        Contacto: personaInfo.CONTACTO,
        ID_VISITANTE,
        Condominio: personaInfo.ID_CONDOMINIO,
        NOMBRE_VISITANTE,
        NACIONALIDAD,
        DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: CARNET_EXTRANJERO,
        NUM_PERSONAS,
        NUM_PLACA,
        FECHA_VENCIMIENTO: fechaVencimiento,
        ID_CONDOMINIO: personaInfo.ID_CONDOMINIO,
      };
    } else {
      qrData = {
        Residente: personaInfo.NOMBRE_PERSONA,
        DNI_Residente: personaInfo.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: personaInfo.NUM_CARNET_EXTRANJERO,
        Contacto: personaInfo.CONTACTO,
        ID_VISITANTE,
        Condominio: personaInfo.ID_CONDOMINIO,
        NOMBRE_VISITANTE,
        NACIONALIDAD,
        DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: CARNET_EXTRANJERO,
        NUM_PERSONAS,
        NUM_PLACA,
        FECHA_HORA: fechaCalculada,
        ID_CONDOMINIO: personaInfo.ID_CONDOMINIO,
      };
    }

    const tokenQR = generarTokenSeguroQR(ID_VISITANTE, isRecurrentVisitor ? "Recurrente" : "Normal");

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    res.status(201).json({
      message: isRecurrentVisitor
        ? "Visitante recurrente registrado exitosamente"
        : "Visita registrada exitosamente",
      qrCode: qrUrl,
      qrData: qrData,
      qrToken: tokenQR,
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Error en el servidor" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});
//Validar el QR por los eventos y validar se es cancelado
app.post("/validateQR", async (req, res) => {
  // Desestructurar el ID_VISITANTE del cuerpo
  const { ID_VISITANTE } = req.body;

  // Validar que el ID_VISITANTE esté presente
  if (!ID_VISITANTE) {
    return res
      .status(400)
      .json({ message: "ID de visitante no proporcionado" });
  }
  let connection;

  try {
    connection = await mysqlPool.getConnection();
    // Verificar si el visitante existe en la base de datos
    const [visitanteResults] = await connection.query(
      "SELECT ESTADO_QR, ESTADO, MOTIVO_CANCELACION FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?",
      [ID_VISITANTE]
    );

    if (visitanteResults.length === 0 || visitanteResults[0].ESTADO === 'Cancelado') {
      const motivo = visitanteResults.length > 0 && visitanteResults[0].MOTIVO_CANCELACION ? ` Motivo: ${visitanteResults[0].MOTIVO_CANCELACION}` : '';
      return res
        .status(400)
        .json({ message: `Código QR cancelado por el Residente.${motivo}` });
    }

    const estadoQR = visitanteResults[0].ESTADO_QR;

    // Obtener el parámetro QR_EVENTOS
    const [parametroResults] = await connection.query(
      "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = 'QR_EVENTOS'"
    );

    if (parametroResults.length === 0) {
      return res
        .status(500)
        .json({ message: "Parámetro QR_EVENTOS no configurado" });
    }

    const valorQREventos = parametroResults[0].VALOR;

    // Validar si el código QR ya fue escaneado
    if (estadoQR == valorQREventos) {
      return res.status(400).json({ message: "Código QR ya escaneado" });
    }

    // Respuesta exitosa
    return res.status(200).json({ message: "Código QR válido" });
  } catch (error) {
    console.error("Error al validar el código QR:", error);
    return res
      .status(500)
      .json({ message: "Error interno al validar el código QR" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

app.post("/consultarQR_detalles", async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: "Codigo QR no proporcionado" });
  }

  let idVisitante;
  let tipo = "Normal";

  if (typeof code === "string" && code.startsWith("VLA_SEC_")) {
    try {
      const descifrado = descifrarTokenSeguroQR(code);
      if (!descifrado || !descifrado.id) {
        return res.status(400).json({ message: "Codigo QR invalido o alterado" });
      }
      idVisitante = descifrado.id;
      tipo = descifrado.tipo || "Normal";
    } catch (e) {
      return res.status(400).json({ message: "Error al descifrar el codigo QR" });
    }
  } else {
    try {
      const parsed = typeof code === "string" ? JSON.parse(code) : code;
      if (parsed.ID_PAQUETE) {
        idVisitante = parsed.ID_PAQUETE;
        tipo = "Paquete";
      } else {
        idVisitante = parsed.ID_VISITANTE;
        tipo = parsed.FECHA_VENCIMIENTO ? "Recurrente" : "Normal";
      }
    } catch (e) {
      return res.status(400).json({ message: "Formato de codigo QR no valido" });
    }
  }

  if (!idVisitante) {
    return res.status(400).json({ message: "No se pudo identificar la visita o paquete en el QR" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    if (tipo === "Paquete") {
      const [paqueteRows] = await connection.query(
        `SELECT p.*, per.NOMBRE_PERSONA AS RESIDENTE, per.DNI_PERSONA,
                c.DESCRIPCION AS CONDOMINIO, u.EMAIL AS EMAIL_RESIDENTE
         FROM TBL_REG_PAQUETES p
         JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
         LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
         LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = per.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
         WHERE p.ID_PAQUETE = ?`,
        [idVisitante]
      );

      if (paqueteRows.length === 0) {
        return res.status(404).json({ message: "Paquete no encontrado en el sistema" });
      }

      const paq = paqueteRows[0];
      const qrData = {
        ID_PAQUETE: paq.ID_PAQUETE,
        Empresa: paq.EMPRESA_REMITENTE,
        TipoRemitente: paq.TIPO_REMITENTE,
        Dimension: paq.DIMENSION,
        Descripcion: paq.DESCRIPCION || "",
        FechaEstimada: paq.FECHA_ESTIMADA_ENTREGA ? parseFechaTegucigalpa(paq.FECHA_ESTIMADA_ENTREGA).format("DD/MM/YYYY hh:mm A") : "",
        Residente: paq.RESIDENTE,
        Condominio: paq.CONDOMINIO || "N/A",
        Estado: paq.ESTADO_PAQUETE,
        EstadoFisico: paq.ESTADO_FISICO,
        Observaciones: paq.OBSERVACIONES_GUARDIA,
        FechaRecepcion: paq.FECHA_RECEPCION ? parseFechaTegucigalpa(paq.FECHA_RECEPCION).format("DD/MM/YYYY hh:mm A") : null,
        UsuarioRecepcion: paq.USUARIO_RECEPCION,
      };

      return res.status(200).json({
        tipo: "Paquete",
        qrData: qrData,
      });
    }

    if (tipo === "Multiple") {
      const [eventoRows] = await connection.query(
        `SELECT e.*, per.NOMBRE_PERSONA AS RESIDENTE, per.DNI_PERSONA,
                c.DESCRIPCION AS CONDOMINIO, u.EMAIL AS EMAIL_RESIDENTE
         FROM TBL_REG_VISITAS_MULTIPLES e
         JOIN TBL_PERSONAS per ON e.ID_PERSONA = per.ID_PERSONA
         LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
         LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = per.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
         WHERE e.ID_VISITA_MULTIPLE = ?`,
        [idVisitante]
      );

      if (eventoRows.length === 0) {
        return res.status(404).json({ message: "Pase de visita múltiple no encontrado o cancelado" });
      }

      const ev = eventoRows[0];
      if (ev.ESTADO === 'Cancelado') {
        const motivo = ev.MOTIVO_CANCELACION ? ` Motivo: ${ev.MOTIVO_CANCELACION}` : '';
        return res.status(400).json({ message: `Este pase de visitas múltiples ha sido cancelado por el residente.${motivo}` });
      }
      const [visitantesRows] = await connection.query(
        `SELECT ID_DETALLE, ID_VISITA_MULTIPLE, NOMBRE_VISITANTE, DOCUMENTO,
                ESTADO_INGRESO, FECHA_INGRESO, OBSERVACIONES_GUARDIA, USUARIO_GUARDIA
         FROM TBL_DETALLE_VISITAS_MULTIPLES
         WHERE ID_VISITA_MULTIPLE = ?
         ORDER BY ID_DETALLE ASC`,
        [idVisitante]
      );

      const fechaHoy = moment().tz("America/Tegucigalpa").format("YYYY-MM-DD");
      const fechaEventoObj = parseFechaTegucigalpa(ev.FECHA_EVENTO);
      const fechaVencimientoObj = parseFechaTegucigalpa(ev.FECHA_VENCIMIENTO);

      const fechaEventoDia = fechaEventoObj.format("YYYY-MM-DD");
      const esFechaValida = (fechaHoy === fechaEventoDia);
      const yaVencido = moment().tz("America/Tegucigalpa").isAfter(fechaVencimientoObj);

      const visitantesFormateados = visitantesRows.map((v) => {
        let estadoIngreso = v.ESTADO_INGRESO || "Pendiente";
        if (ev.ESTADO === "Cancelado" && estadoIngreso !== "Ingresado") {
          estadoIngreso = "Cancelado";
        } else if (estadoIngreso === "Pendiente" && yaVencido) {
          estadoIngreso = "No se presentó";
        }
        return {
          ID_DETALLE: v.ID_DETALLE,
          NombreCompleto: v.NOMBRE_VISITANTE,
          Documento: v.DOCUMENTO || "",
          EstadoIngreso: estadoIngreso,
          FechaIngreso: v.FECHA_INGRESO ? parseFechaTegucigalpa(v.FECHA_INGRESO).format("DD/MM/YYYY hh:mm A") : null,
          ObservacionesGuardia: v.OBSERVACIONES_GUARDIA || "",
          UsuarioGuardia: v.USUARIO_GUARDIA || "",
        };
      });

      const totalInvitados = visitantesFormateados.length;
      const totalIngresados = visitantesFormateados.filter((v) => v.EstadoIngreso === "Ingresado").length;

      const qrData = {
        ID_VISITA_MULTIPLE: ev.ID_VISITA_MULTIPLE,
        TituloEvento: ev.TITULO_EVENTO,
        ObservacionesResidente: ev.OBSERVACIONES_RESIDENTE || "",
        FechaEvento: fechaEventoObj.format("DD/MM/YYYY hh:mm A"),
        FechaEventoCorta: fechaEventoObj.format("DD/MM/YYYY"),
        FechaVencimiento: fechaVencimientoObj.format("DD/MM/YYYY hh:mm A"),
        Residente: ev.RESIDENTE,
        Condominio: ev.CONDOMINIO || "N/A",
        Estado: ev.ESTADO,
        MotivoCancelacion: ev.MOTIVO_CANCELACION || "",
        EsFechaValida: esFechaValida,
        YaVencido: yaVencido,
        TotalInvitados: totalInvitados,
        TotalIngresados: totalIngresados,
        Visitantes: visitantesFormateados,
      };

      return res.status(200).json({
        tipo: "Multiple",
        qrData: qrData,
      });
    }

    let query;
    if (tipo === "Recurrente") {
      query = "SELECT * FROM TBL_VISITANTES_RECURRENTES WHERE ID_VISITANTES_RECURRENTES = ?";
    } else {
      query = "SELECT * FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?";
    }

    const [visitaRows] = await connection.query(query, [idVisitante]);
    if (visitaRows.length === 0) {
      return res.status(404).json({ message: "Visita no encontrada o cancelada" });
    }

    const v = visitaRows[0];
    if (v.ESTADO === 'Cancelado') {
      const motivo = v.MOTIVO_CANCELACION ? ` Motivo: ${v.MOTIVO_CANCELACION}` : '';
      return res.status(400).json({ message: `Esta visita ha sido cancelada por el residente.${motivo}` });
    }
    const idPersona = v.ID_PERSONA;

    const [personaInfoResults] = await connection.query(
      `SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, p.NUM_CARNET_EXTRANJERO, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
       FROM TBL_PERSONAS p
       LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
       LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
       WHERE p.ID_PERSONA = ?`,
      [idPersona]
    );

    if (personaInfoResults.length === 0) {
      return res.status(404).json({ message: "Informacion del residente no encontrada" });
    }

    const p = personaInfoResults[0];
    const [nac] = await connection.query("SELECT NOMBRE_NACIONALIDAD FROM TBL_NACIONALIDADES WHERE ID_NACIONALIDAD = ?", [v.ID_NACIONALIDAD]);
    const nacionalidadStr = nac.length > 0 ? nac[0].NOMBRE_NACIONALIDAD : "N/A";

    let qrData;
    if (tipo === "Recurrente") {
      qrData = {
        Residente: p.NOMBRE_PERSONA,
        DNI_Residente: p.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: p.NUM_CARNET_EXTRANJERO,
        Contacto: p.CONTACTO,
        ID_VISITANTE: Number(idVisitante),
        Condominio: p.ID_CONDOMINIO,
        NOMBRE_VISITANTE: v.NOMBRE_VISITANTE,
        NACIONALIDAD: nacionalidadStr,
        DNI_VISITANTE: v.DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: v.NUM_CARNET_EXTRANJERO,
        NUM_PERSONAS: v.NUM_PERSONAS,
        NUM_PLACA: v.NUM_PLACA,
        FECHA_VENCIMIENTO: moment(v.FECHA_VENCIMIENTO).format("YYYY-MM-DD HH:mm:ss"),
        ID_CONDOMINIO: p.ID_CONDOMINIO,
      };
    } else {
      const [bitacora] = await connection.query("SELECT FECHA_VENCIMIENTO FROM TBL_BITACORA_VISITA WHERE ID_VISITANTE = ?", [idVisitante]);
      const fechaVence = bitacora.length > 0 ? moment(bitacora[0].FECHA_VENCIMIENTO).format("YYYY-MM-DD HH:mm:ss") : moment(v.FECHA_HORA).add(24, 'hours').format("YYYY-MM-DD HH:mm:ss");

      qrData = {
        Residente: p.NOMBRE_PERSONA,
        DNI_Residente: p.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: p.NUM_CARNET_EXTRANJERO,
        Contacto: p.CONTACTO,
        ID_VISITANTE: Number(idVisitante),
        Condominio: p.ID_CONDOMINIO,
        NOMBRE_VISITANTE: v.NOMBRE_VISITANTE,
        NACIONALIDAD: nacionalidadStr,
        DNI_VISITANTE: v.DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: v.NUM_CARNET_EXTRANJERO,
        NUM_PERSONAS: v.NUM_PERSONAS,
        NUM_PLACA: v.NUM_PLACA,
        FECHA_HORA: fechaVence,
        ID_CONDOMINIO: p.ID_CONDOMINIO,
      };
    }

    return res.status(200).json({
      tipo: tipo,
      qrData: qrData,
    });
  } catch (error) {
    console.error("Error al consultar detalles de QR:", error);
    return res.status(500).json({ message: "Error interno al procesar el codigo QR" });
  } finally {
    if (connection) connection.release();
  }
});


//Eliminar las visitas Recurrentes
app.post("/eliminarVisitaRecurrentes", async (req, res) => {
  const { ID_VISITANTE, motivo } = req.body;
  const motivoCancelacion = motivo || "Cancelado por el residente";

  if (!ID_VISITANTE) {
    return res.status(400).json({ message: "ID_VISITANTE es requerido" });
  }

  try {
    const connection = await mysqlPool.getConnection();

    try {
      await connection.beginTransaction();

      await connection.query(
        "UPDATE TBL_BITACORA_VISITA SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTES_RECURRENTES = ?",
        [motivoCancelacion, ID_VISITANTE]
      );

      const [updateResult] = await connection.query(
        "UPDATE TBL_VISITANTES_RECURRENTES SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTES_RECURRENTES = ?",
        [motivoCancelacion, ID_VISITANTE]
      );

      await connection.commit();
      connection.release();

      if (updateResult.affectedRows === 0) {
        return res.status(404).json({ message: "Visitante no encontrado" });
      }

      return res
        .status(200)
        .json({ message: "Visita recurrente cancelada exitosamente" });
    } catch (queryError) {
      await connection.rollback();
      connection.release();
      console.error("Error en transacción:", queryError);
      return res
        .status(500)
        .json({ message: "Error cancelando visita recurrente" });
    }
  } catch (error) {
    console.error("Error conectando a la base de datos:", error);
    return res
      .status(500)
      .json({ message: "Error de conexión a la base de datos" });
  }
});

//Eliminar visitas No recurrentes
app.post("/eliminarVisitaNoRecurrentes", async (req, res) => {
  const { ID_VISITANTE, motivo } = req.body;
  const motivoCancelacion = motivo || "Cancelado por el residente";

  if (!ID_VISITANTE) {
    return res.status(400).json({ message: "ID_VISITANTE es requerido" });
  }

  try {
    const connection = await mysqlPool.getConnection();

    try {
      await connection.beginTransaction();

      await connection.query(
        "UPDATE TBL_BITACORA_VISITA SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTE = ?",
        [motivoCancelacion, ID_VISITANTE]
      );

      const [updateResult] = await connection.query(
        "UPDATE TBL_REGVISITAS SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTE = ?",
        [motivoCancelacion, ID_VISITANTE]
      );

      await connection.commit();
      connection.release();

      if (updateResult.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "Visitante no recurrente no encontrado" });
      }

      return res
        .status(200)
        .json({ message: "Visita no recurrente cancelada exitosamente" });
    } catch (queryError) {
      await connection.rollback();
      connection.release();
      console.error("Error en transacción:", queryError);
      return res
        .status(500)
        .json({ message: "Error cancelando visita no recurrente" });
    }
  } catch (error) {
    console.error("Error conectando a la base de datos:", error);
    return res
      .status(500)
      .json({ message: "Error de conexión a la base de datos" });
  }
});

app.post("/cancelarVisitaIndividual", async (req, res) => {
  const { ID_VISITANTE, tipo, motivo } = req.body;
  const motivoCancelacion = motivo || "Cancelado por el residente";

  if (!ID_VISITANTE) {
    return res.status(400).json({ message: "ID_VISITANTE es requerido" });
  }

  const isRecurrente = tipo === "Recurrente";
  try {
    const connection = await mysqlPool.getConnection();

    try {
      await connection.beginTransaction();

      if (isRecurrente) {
        await connection.query(
          "UPDATE TBL_BITACORA_VISITA SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTES_RECURRENTES = ?",
          [motivoCancelacion, ID_VISITANTE]
        );
        await connection.query(
          "UPDATE TBL_VISITANTES_RECURRENTES SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTES_RECURRENTES = ?",
          [motivoCancelacion, ID_VISITANTE]
        );
      } else {
        await connection.query(
          "UPDATE TBL_BITACORA_VISITA SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTE = ?",
          [motivoCancelacion, ID_VISITANTE]
        );
        await connection.query(
          "UPDATE TBL_REGVISITAS SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITANTE = ?",
          [motivoCancelacion, ID_VISITANTE]
        );
      }

      await connection.commit();
      connection.release();

      return res.status(200).json({ message: "Visita cancelada exitosamente" });
    } catch (queryError) {
      await connection.rollback();
      connection.release();
      return res.status(500).json({ message: "Error cancelando la visita" });
    }
  } catch (error) {
    return res.status(500).json({ message: "Error de conexión a la base de datos" });
  }
});

//Validar el QR Recurrentes si esta cancelado el QR
app.post("/validateQR_Recurrentes", async (req, res) => {
  // Desestructurar el ID_VISITANTE del cuerpo
  const { ID_VISITANTE } = req.body;

  // Validar que el ID_VISITANTE esté presente
  if (!ID_VISITANTE) {
    return res
      .status(400)
      .json({ message: "ID de visitante no proporcionado" });
  }
  let connection;

  try {
    connection = await mysqlPool.getConnection();
    // Verificar si el visitante existe en la base de datos
    const [visitanteResults] = await connection.query(
      "SELECT ID_VISITANTES_RECURRENTES, ESTADO, MOTIVO_CANCELACION FROM TBL_VISITANTES_RECURRENTES WHERE ID_VISITANTES_RECURRENTES = ?",
      [ID_VISITANTE]
    );

    if (visitanteResults.length === 0 || visitanteResults[0].ESTADO === 'Cancelado') {
      const motivo = visitanteResults.length > 0 && visitanteResults[0].MOTIVO_CANCELACION ? ` Motivo: ${visitanteResults[0].MOTIVO_CANCELACION}` : '';
      return res
        .status(400)
        .json({ message: `Código QR cancelado por el Residente.${motivo}` });
    }

    // Respuesta exitosa
    return res.status(200).json({ message: "Código QR válido" });
  } catch (error) {
    console.error("Error al validar el código QR:", error);
    return res
      .status(500)
      .json({ message: "Error interno al validar el código QR" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});


/****************************************** */
//Incrementar el estado del qr
app.post("/incrementarEstadoQR", async (req, res) => {
  const { ID_VISITANTE } = req.body;
  console.log("Datos recibidos QR:", { ID_VISITANTE });

  if (!ID_VISITANTE) {
    return res
      .status(400)
      .json({ message: "ID de visitante no proporcionado" });
  }
  try {
    const connection = await mysqlPool.getConnection();

    const [visitanteResults] = await connection.query(
      `SELECT r.ESTADO_QR, r.NOMBRE_VISITANTE, r.NUM_PLACA, p.ID_CONDOMINIO, u.ID_USUARIO, c.DESCRIPCION AS CONDOMINIO
       FROM TBL_REGVISITAS r
       JOIN TBL_PERSONAS p ON r.ID_PERSONA = p.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
       LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE r.ID_VISITANTE = ?`,
      [ID_VISITANTE]
    );

    if (visitanteResults.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Visitante no encontrado" });
    }

    const visita = visitanteResults[0];
    const estadoQR = visita.ESTADO_QR;
    const nuevoEstadoQR = estadoQR + 1;
    await connection.query(
      "UPDATE TBL_REGVISITAS SET ESTADO_QR = ? WHERE ID_VISITANTE = ?",
      [nuevoEstadoQR, ID_VISITANTE]
    );

    const now = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const formatDate = now.toISOString().slice(0, 19).replace("T", " ");

    await connection.query(
      "UPDATE TBL_REGVISITAS SET FECHA_ACCESO = ? WHERE ID_VISITANTE = ?",
      [formatDate, ID_VISITANTE]
    );

    await connection.query(
      "UPDATE TBL_BITACORA_VISITA SET FECHA_ACCESO = ? WHERE ID_VISITANTE = ?",
      [formatDate, ID_VISITANTE]
    );

    connection.release();

    if (visita.ID_USUARIO) {
      pushService.notificarUsuario(mysqlPool, visita.ID_USUARIO, {
        titulo: "Visita ingresó a la residencial",
        mensaje: `Tu visitante ${visita.NOMBRE_VISITANTE || ''} ha ingresado por caseta.`,
        tipo: "VISITA",
        data: {
          ruta: "/visitas",
          idVisitante: ID_VISITANTE
        }
      }).catch(err => console.error("Error push visitante usuario:", err));
    }

    if (visita.ID_CONDOMINIO) {
      pushService.notificarAdminCondominio(mysqlPool, visita.ID_CONDOMINIO, {
        titulo: "Visita ingresó a la vivienda",
        mensaje: `Visita ${visita.NOMBRE_VISITANTE || ''} para ${visita.CONDOMINIO || 'tu vivienda'} ha ingresado por caseta.`,
        tipo: "VISITA",
        data: {
          ruta: "/visitas",
          idVisitante: ID_VISITANTE
        }
      }).catch(err => console.error("Error push visitante condominio:", err));
    }

    return res
      .status(200)
      .json({ message: "Estado QR incrementado exitosamente" });
  } catch (error) {
    console.error("Error al incrementar el estado del QR:", error);
    return res.status(500).json({ error: "Error al procesar la solicitud" });
  }
});

// Actualizar fecha de acceso a visitantes recurrentes
app.post("/actualizarFechaAccesoRecurrente", async (req, res) => {
  const { ID_VISITANTE } = req.body;
  if (!ID_VISITANTE) {
    console.error("Error: ID de visitante no proporcionado en la solicitud.");
    // Devolver una respuesta 400 (Bad Request) al cliente
    return res.status(400).json({
      message:
        "ID de visitante no proporcionado. La solicitud no puede ser procesada.",
    });
  }

  let connection; // Declarar la variable de conexión fuera del bloque try
  try {
    connection = await mysqlPool.getConnection();
    const nowInUTC6 = new Date();
    nowInUTC6.setHours(nowInUTC6.getHours() - 6);
    const formattedDate = nowInUTC6
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    console.log(`Fecha actual en UTC-6 para actualizar: ${formattedDate}`);

    const [resultBitacora] = await connection.query(
      "UPDATE TBL_BITACORA_VISITA SET FECHA_ACCESO = ? WHERE ID_VISITANTES_RECURRENTES = ?",
      [formattedDate, ID_VISITANTE]
    );

    //Actualizar la fecha de acceso de TBL_VISITANTESrECURRENTES
    const [resultRecurrente] = await connection.query(
      "UPDATE TBL_VISITANTES_RECURRENTES SET FECHA_ACCESO = ? WHERE ID_VISITANTES_RECURRENTES = ?",
      [formattedDate, ID_VISITANTE]
    );
    // 5. Verificar si alguna fila fue afectada por la actualización
    if (resultBitacora.affectedRows === 0) {
      console.warn(
        `Advertencia: No se encontró ningún registro para el de Bitacora ${ID_VISITANTE}.`
      );
      // Se puede devolver un 200 (OK) o 404 (Not Found) dependiendo del comportamiento deseado
      return res.status(404).json({
        message:
          "No se encontró el visitante recurrente con ese ID para actualizar.",
      });
    }

    if (resultRecurrente.affectedRows === 0) {
      console.warn(
        `Advertencia: No se encontró ningún registro para el Visiatnte Recurrentes ${ID_VISITANTE}.`
      );
      return res.status(404).json({
        message:
          "No se encontró el visitante recurrente con ese ID para actualizar.",
      });
    }

    const [recResults] = await connection.query(
      `SELECT r.NOMBRE_VISITANTE, r.NUM_PLACA, p.ID_CONDOMINIO, u.ID_USUARIO, c.DESCRIPCION AS CONDOMINIO
       FROM TBL_VISITANTES_RECURRENTES r
       JOIN TBL_PERSONAS p ON r.ID_PERSONA = p.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
       LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE r.ID_VISITANTES_RECURRENTES = ?`,
      [ID_VISITANTE]
    );

    if (recResults.length > 0) {
      const rec = recResults[0];
      if (rec.ID_USUARIO) {
        pushService.notificarUsuario(mysqlPool, rec.ID_USUARIO, {
          titulo: "Visitante frecuente ingresó a la residencial",
          mensaje: `Tu visitante frecuente ${rec.NOMBRE_VISITANTE || ''} ha ingresado por caseta.`,
          tipo: "VISITA_RECURRENTE",
          data: {
            ruta: "/visitas",
            idVisitanteRecurrente: ID_VISITANTE
          }
        }).catch(err => console.error("Error push recurrente usuario:", err));
      }

      if (rec.ID_CONDOMINIO) {
        pushService.notificarAdminCondominio(mysqlPool, rec.ID_CONDOMINIO, {
          titulo: "Visitante frecuente ingresó a la vivienda",
          mensaje: `Visitante frecuente ${rec.NOMBRE_VISITANTE || ''} para ${rec.CONDOMINIO || 'tu vivienda'} ha ingresado.`,
          tipo: "VISITA_RECURRENTE",
          data: {
            ruta: "/visitas",
            idVisitanteRecurrente: ID_VISITANTE
          }
        }).catch(err => console.error("Error push recurrente condominio:", err));
      }
    }

    return res.status(200).json({
      message: "Fecha de acceso actualizada exitosamente.",
    });
  } catch (error) {
    // 7. Manejo de errores: Capturar cualquier excepción que ocurra
    console.error(
      "Error al actualizar la fecha de acceso del visitante recurrente:",
      error
    );
    // Devolver una respuesta 500 (Internal Server Error)
    return res
      .status(500)
      .json({ error: "Error interno del servidor al procesar la solicitud." });
  } finally {
    // 8. Liberar la conexión SIEMPRE
    if (connection) {
      connection.release();
      console.log("Conexión a la base de datos liberada.");
    }
  }
});

// Crear un endpoint para obtener todos los anuncios
app.get("/anuncios_eventos", async (req, res) => {
  const usuarioId = req.query.usuario_id;

  const query = `
    SELECT ID_ANUNCIOS_EVENTOS, TITULO, DESCRIPCION, IMAGEN, FECHA_HORA 
    FROM TBL_ANUNCIOS_EVENTOS 
    WHERE ID_ESTADO_ANUNCIO_EVENTO = 1 
    AND ID_ANUNCIOS_EVENTOS NOT IN (
        SELECT ID_ANUNCIOS_EVENTOS FROM TBL_ANUNCIOS_OCULTOS WHERE ID_USUARIO = ?
    )
    ORDER BY FECHA_HORA DESC`;
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(query, [usuarioId]);
    res.status(200).json(results);
  } catch (error) {
    console.error("Error al obtener los anuncios:", error);
    res.status(500).send("Error al obtener los anuncios");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// Endpoint para ocultar un anuncio
app.post("/ocultar_anuncio", async (req, res) => {
  const { usuarioId, anuncioId } = req.body;

  console.log("Datos recibidos:", req.body);

  const query = `
    INSERT INTO TBL_ANUNCIOS_OCULTOS (ID_USUARIO, ID_ANUNCIOS_EVENTOS) 
    VALUES (?, ?)`;
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.query(query, [usuarioId, anuncioId]);
    res.status(200).send("Anuncio ocultado exitosamente");
  } catch (error) {
    console.error("Error al ocultar el anuncio:", error);
    res.status(500).send("Error al ocultar el anuncio");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// Crear un endpoint para obtener los datos del perfil del usuario
app.get("/perfil", async (req, res) => {
  const usuarioId = req.query.usuario_id;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // 1. Obtener datos del usuario
    const [userResults] = await connection.query(
      "SELECT NOMBRE_USUARIO, EMAIL, ID_ROL FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (userResults.length === 0) {
      console.log(`Usuario con ID ${usuarioId} no encontrado`);
      return res.status(404).send("Usuario no encontrado");
    }

    const user = userResults[0];

    // 2. Obtener ID_PADRE del residente usando el NOMBRE_USUARIO
    let idPadre = null;
    let nombrePersona = user.NOMBRE_USUARIO;
    let descripcionCondominio = "Villa Las Acacias";
    try {
      const [personaResults] = await connection.query(
        `SELECT p.ID_PADRE, p.NOMBRE_PERSONA, c.DESCRIPCION AS CONDOMINIO
         FROM TBL_PERSONAS p
         LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
         WHERE p.NOMBRE_PERSONA = ?`,
        [user.NOMBRE_USUARIO]
      );
      if (personaResults.length > 0) {
        idPadre = personaResults[0].ID_PADRE;
        if (personaResults[0].NOMBRE_PERSONA) {
          nombrePersona = personaResults[0].NOMBRE_PERSONA;
        }
        if (personaResults[0].CONDOMINIO) {
          descripcionCondominio = personaResults[0].CONDOMINIO;
        }
      }
    } catch (personaError) {
      console.error("Error al obtener ID_PADRE de TBL_PERSONAS:", personaError);
    }

    // 3. Devolver los datos combinados
    res.status(200).json({
      NOMBRE_USUARIO: user.NOMBRE_USUARIO,
      NOMBRE_PERSONA: nombrePersona,
      CONDOMINIO: descripcionCondominio,
      DESCRIPCION: descripcionCondominio,
      EMAIL: user.EMAIL,
      ID_ROL: user.ID_ROL,
      ID_PADRE: idPadre,
    });
  } catch (error) {
    console.error("Error al obtener el perfil del usuario:", error);
    res.status(500).send("Error al obtener el perfil del usuario");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** Consultar Reservaciones *********
app.get("/consultar_reservaciones", async (req, res) => {
  const usuarioId = req.query.usuario_id;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (!usuarioResults.length) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (!personaResults.length) {
      return res.status(404).json({ error: "Persona no encontrada" });
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

    res.json(reservasResults);
  } catch (error) {
    console.error("Error al obtener las reservas:", error);
    res.status(500).json({ error: "Error al obtener las reservas" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** Consultar Visitas *********
app.get("/consultar_visitas", async (req, res) => {
  const usuarioId = req.query.usuario_id;
  const all = req.query.all === "true" || req.query.all === "1";

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (!usuarioResults.length) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA y el ID_CONDOMINIO de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (!personaResults.length) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;
    const ID_CONDOMINIO = personaResults[0].ID_CONDOMINIO;

    let queryRegVisitas, queryVisitantesRecurrentes, queryParams;

    if (all) {
      queryRegVisitas = `
      SELECT v.ID_VISITANTE, v.NOMBRE_VISITANTE, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, v.NUM_PERSONAS, v.NUM_PLACA, 
             DATE_FORMAT(v.FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
             NULL AS FECHA_VENCIMIENTO, 
             'No recurrente' AS TIPO,
             p.NOMBRE_PERSONA AS CREADO_POR,
             COALESCE(v.ESTADO, 'Activo') AS ESTADO,
             v.MOTIVO_CANCELACION
      FROM TBL_REGVISITAS v
      JOIN TBL_PERSONAS p ON v.ID_PERSONA = p.ID_PERSONA
      WHERE p.ID_CONDOMINIO = ?`;

      queryVisitantesRecurrentes = `
      SELECT v.ID_VISITANTES_RECURRENTES, v.NOMBRE_VISITANTE, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, v.NUM_PERSONAS, v.NUM_PLACA, 
             DATE_FORMAT(v.FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
             DATE_FORMAT(v.FECHA_VENCIMIENTO, '%d/%m/%Y %H:%i') AS FECHA_VENCIMIENTO, 
             'Recurrente' AS TIPO,
             p.NOMBRE_PERSONA AS CREADO_POR,
             COALESCE(v.ESTADO, 'Activo') AS ESTADO,
             v.MOTIVO_CANCELACION
      FROM TBL_VISITANTES_RECURRENTES v
      JOIN TBL_PERSONAS p ON v.ID_PERSONA = p.ID_PERSONA
      WHERE p.ID_CONDOMINIO = ?`;

      queryParams = [ID_CONDOMINIO];
    } else {
      queryRegVisitas = `
      SELECT v.ID_VISITANTE, v.NOMBRE_VISITANTE, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, v.NUM_PERSONAS, v.NUM_PLACA, 
             DATE_FORMAT(v.FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
             NULL AS FECHA_VENCIMIENTO, 
             'No recurrente' AS TIPO,
             p.NOMBRE_PERSONA AS CREADO_POR,
             COALESCE(v.ESTADO, 'Activo') AS ESTADO,
             v.MOTIVO_CANCELACION
      FROM TBL_REGVISITAS v
      JOIN TBL_PERSONAS p ON v.ID_PERSONA = p.ID_PERSONA
      WHERE v.ID_PERSONA = ?`;

      queryVisitantesRecurrentes = `
      SELECT v.ID_VISITANTES_RECURRENTES, v.NOMBRE_VISITANTE, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, v.NUM_PERSONAS, v.NUM_PLACA, 
             DATE_FORMAT(v.FECHA_HORA, '%d/%m/%Y %H:%i') AS FECHA_HORA, 
             DATE_FORMAT(v.FECHA_VENCIMIENTO, '%d/%m/%Y %H:%i') AS FECHA_VENCIMIENTO, 
             'Recurrente' AS TIPO,
             p.NOMBRE_PERSONA AS CREADO_POR,
             COALESCE(v.ESTADO, 'Activo') AS ESTADO,
             v.MOTIVO_CANCELACION
      FROM TBL_VISITANTES_RECURRENTES v
      JOIN TBL_PERSONAS p ON v.ID_PERSONA = p.ID_PERSONA
      WHERE v.ID_PERSONA = ?`;

      queryParams = [ID_PERSONA];
    }

    const [regVisitasResults] = await connection.query(queryRegVisitas, queryParams);
    const [visitantesRecurrentesResults] = await connection.query(
      queryVisitantesRecurrentes,
      queryParams
    );

    // Combinar los resultados de ambas consultas
    const resultados = [...regVisitasResults, ...visitantesRecurrentesResults];

    // Retornar los resultados a la aplicación Flutter
    res.json(resultados);
  } catch (error) {
    console.error("Error al consultar visitas:", error);
    res.status(500).json({ error: "Error al consultar visitas" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// Ruta para consultar reservaciones futuras
app.get("/consulta_reservaciones_futuras", async (req, res) => {
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
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).send("Error en el servidor");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// ***********   Ruta para obtener los horarios de las reservaciones
app.get("/obtener_horarios", async (req, res) => {
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
        Días: "Lunes a viernes",
        Horarios: `${
          results.find(
            (row) => row.PARAMETRO === "HORARIO_LUNES_VIERNES_MANAÑA"
          )?.VALOR || "No disponible"
        } y ${
          results.find((row) => row.PARAMETRO === "HORARIO_LUNES_VIERNES_TARDE")
            ?.VALOR || "No disponible"
        }`,
      },
      {
        Días: "Sábado",
        Horarios: `${
          results.find((row) => row.PARAMETRO === "HORARIO_SABADO_MANAÑA")
            ?.VALOR || "No disponible"
        } y ${
          results.find((row) => row.PARAMETRO === "HORARIO_SABADO_TARDE")
            ?.VALOR || "No disponible"
        }`,
      },
      {
        Días: "Domingo",
        Horarios: `${
          results.find((row) => row.PARAMETRO === "HORARIO_DOMINGO_MANAÑA")
            ?.VALOR || "No disponible"
        } y ${
          results.find((row) => row.PARAMETRO === "HORARIO_DOMINGO_TARDE")
            ?.VALOR || "No disponible"
        }`,
      },
    ];

    // Retornar los horarios formateados
    res.json(horarios);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).send("Error en el servidor");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********* Consultar familia ************
app.get("/consultar_familia", async (req, res) => {
  const usuarioId = req.query.usuario_id;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO de la tabla TBL_MS_USUARIO usando usuarioId
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (!usuarioResults.length) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA y el ID_CONDOMINIO de la tabla TBL_PERSONAS usando el nombreUsuario
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (!personaResults.length) {
      return res.status(404).json({ error: "Persona no encontrada" });
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

    const [personasResults] = await connection.query(queryPersonas, [
      ID_CONDOMINIO,
    ]);

    // Retornar los resultados a la aplicación Flutter
    res.json(personasResults);
  } catch (error) {
    console.error("Error al consultar la familia:", error);
    res.status(500).json({ error: "Error al consultar la familia" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** Insertar Reserva *****
app.post("/nueva_reserva", async (req, res) => {
  const { usuarioId, nombreInstalacion, tipoEvento, horaFecha } = req.body;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // Obtener el NOMBRE_USUARIO usando el usuarioId
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (!usuarioResults.length) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener datos de la persona
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, NOMBRE_PERSONA, DNI_PERSONA, ID_CONTACTO, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (!personaResults.length) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const {
      ID_PERSONA,
      NOMBRE_PERSONA,
      DNI_PERSONA,
      ID_CONTACTO,
      ID_CONDOMINIO,
    } = personaResults[0];

    // Obtener la DESCRIPCION del contacto
    const [contactoResults] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_CONTACTOS WHERE ID_CONTACTO = ?",
      [ID_CONTACTO]
    );

    if (!contactoResults.length) {
      return res.status(404).json({ error: "Contacto no encontrado" });
    }

    const P_CONTACTO = contactoResults[0].DESCRIPCION;

    // Obtener la DESCRIPCION del condominio
    const [condominioResults] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_CONDOMINIOS WHERE ID_CONDOMINIO = ?",
      [ID_CONDOMINIO]
    );

    if (!condominioResults.length) {
      return res.status(404).json({ error: "Condominio no encontrado" });
    }

    const P_CONDOMINIO = condominioResults[0].DESCRIPCION;

    // Buscar ID_INSTALACION por nombre
    const [instalacionResults] = await connection.query(
      "SELECT ID_INSTALACION FROM TBL_INSTALACIONES WHERE NOMBRE_INSTALACION = ?",
      [nombreInstalacion]
    );

    if (!instalacionResults.length) {
      return res.status(404).json({ error: "Instalación no encontrada" });
    }

    const ID_INSTALACION = instalacionResults[0].ID_INSTALACION;

    const horaFechaYMDHM = moment
      .tz(horaFecha, "DD-MM-YYYY HH:mm", "America/Tegucigalpa")
      .format("YYYY-MM-DD HH:mm:ss");

    // const horaFechaYMDHM = moment(horaFecha, 'DD-MM-YYYY HH:mm').format('YYYY-MM-DD HH:mm:ss');

    // Determinar el día de la semana
    const diaSemana = new Date(horaFechaYMDHM).getDay();
    let jornada = "";

    // Determinar si la reserva es por la mañana o la tarde
    const horaReserva = new Date(horaFechaYMDHM).getHours();

    if (horaReserva < 13) {
      jornada =
        diaSemana >= 1 && diaSemana <= 5
          ? "HORARIO_LUNES_VIERNES_MANAÑA"
          : diaSemana === 6
          ? "HORARIO_SABADO_MANAÑA"
          : "HORARIO_DOMINGO_MANAÑA";
    } else {
      jornada =
        diaSemana >= 1 && diaSemana <= 5
          ? "HORARIO_LUNES_VIERNES_TARDE"
          : diaSemana === 6
          ? "HORARIO_SABADO_TARDE"
          : "HORARIO_DOMINGO_TARDE";
    }

    // Obtener los horarios permitidos para la jornada seleccionada
    const [parametrosResults] = await connection.query(
      "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = ?",
      [jornada]
    );

    if (!parametrosResults.length) {
      return res
        .status(500)
        .json({ error: "No se pudo obtener el horario permitido" });
    }

    const [horaInicio, horaFin] = parametrosResults[0].VALOR.split("-").map(
      (h) => h.trim()
    );

    // Verificar si la hora solicitada está dentro del horario permitido
    const hora = horaFechaYMDHM.split(" ")[1];
    if (hora < horaInicio || hora > horaFin) {
      return res.status(400).json({
        error:
          "El horario ingresado no está permitido según los parámetros configurados",
      });
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
      return res.status(400).json({ error: "Horario ya reservado" });
    }

    // Insertar la reserva si no hay conflicto
    const [insertResult] = await connection.query(
      "INSERT INTO TBL_RESERVAS (ID_PERSONA, ID_INSTALACION, ID_ESTADO_RESERVA, TIPO_EVENTO, HORA_FECHA) VALUES (?, ?, 3, ?, ?)",
      [ID_PERSONA, ID_INSTALACION, tipoEvento, horaFechaYMDHM]
    );
    //pasar de formato la fecha de la reservación
    const horaFechaDMAHMS = moment(horaFechaYMDHM).format("DD-MM-YYYY HH:mm");

    // Obtener los correos de los administradores
    const [adminEmails] = await mysqlPool.query(
      "SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4)"
    );
    const emailList = adminEmails.map((row) => row.EMAIL);
    const mailOptions = {
      from: "villalasacacias@villalasacacias.com",
      to: emailList,
      subject: "Nueva reservación",
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
      `,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error("Error al enviar el correo:", err);
        return res.status(500).json({ error: "Error al enviar el correo" });
      }
      console.log("Correo enviado a:", emailList);
    });

    try {
      const [userRows] = await connection.query(
        `SELECT u.ID_USUARIO 
         FROM TBL_PERSONAS p 
         JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci 
         WHERE p.ID_PERSONA = ?`,
        [ID_PERSONA]
      );
      if (userRows.length > 0) {
        pushService.notificarUsuario(mysqlPool, userRows[0].ID_USUARIO, {
          titulo: "Reservación Solicitada",
          mensaje: `Tu solicitud para reservar ${nombreInstalacion} el ${horaFechaDMAHMS} ha sido registrada.`,
          tipo: "RESERVA",
          data: { ruta: "/reservaciones" },
        }).catch(() => {});
      }

      pushService.notificarRoles(mysqlPool, [1, 4], {
        titulo: "Nueva Reservación Solicitada",
        mensaje: `${NOMBRE_PERSONA} (${P_CONDOMINIO}) reservó ${nombreInstalacion} para ${horaFechaDMAHMS}`,
        tipo: "RESERVA",
        data: { ruta: "/reservaciones" },
      }).catch(() => {});
    } catch (ePush) {
      console.error("Error al enviar push de reservacion:", ePush);
    }

    res.status(201).json({
      message: "Reserva creada exitosamente",
      reservaId: insertResult.insertId,
    });
  } catch (error) {
    console.error("Error al crear la reserva:", error);
    res.status(500).json({ error: "Error al crear la reserva" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

// ******* Tipos de Instalaciones *******
app.get("/instalaciones", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT NOMBRE_INSTALACION FROM TBL_INSTALACIONES"
    );
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//Actualizar el estado de 2FA
app.post("/set2FAStatus", async (req, res) => {
  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.error("Token no proporcionado");
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // Verificar y decodificar el token
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    const { enabled } = req.body;
    if (typeof enabled !== "number" || (enabled !== 0 && enabled !== 1)) {
      return res.status(400).json({ message: "Valor inválido para 2FA" });
    }

    // Actualizar el estado de 2FA en la base de datos
    connection = await mysqlPool.getConnection();
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET CODIGO_2FA = ? WHERE ID_USUARIO = ?",
      [enabled, userId]
    );

    res.json({ message: "Estado de 2FA actualizado correctamente" });
  } catch (error) {
    console.error(
      "Error al verificar el token o actualizar el estado de 2FA:",
      error
    );
    res.status(500).json({ message: "Error interno del servidor" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//************** GET para estado de la persona *************
app.get("/personas", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_ESTADO_PERSONA"
    );
    connection.release();
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//****** para mostrar la nacionalidad */
app.get("/nacionalidad", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT NOMBRE_NACIONALIDAD FROM TBL_NACIONALIDADES"
    );
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

app.get("/contacto", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_TIPO_CONTACTO"
    );
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

app.get("/parentesco", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_PARENTESCOS"
    );
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

app.get("/condominio", async (req, res) => {
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    const [results] = await connection.query(
      "SELECT DESCRIPCION FROM TBL_CONDOMINIOS"
    );
    connection.release();
    res.json(results);
  } catch (err) {
    console.error("Error al ejecutar la consulta:", err);
    res.status(500).json({ error: "Error al ejecutar la consulta" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********* NUEVA PERSONA *********
app.post("/nueva_persona", async (req, res) => {
  const {
    usuarioId,
    P_DNI,
    P_NUM_CARNET_EXTRANJERO,
    P_ID_NACIONALIDAD,
    P_TIPO_CONTACTO,
    P_CONTACTO,
    P_PARENTESCO,
    P_CONDOMINIO, // Este es la descripción del condominio
  } = req.body;

  // AQUI ES DONDE IMPRIMES LOS DATOS EN LA CONSOLA
  console.log(
    "--- Datos recibidos en el cuerpo de la solicitud (req.body) ---"
  );
  console.log("usuarioId:", usuarioId);
  console.log("P_DNI:", P_DNI);
  console.log("P_NUM_CARNET_EXTRANJERO:", P_NUM_CARNET_EXTRANJERO);
  console.log("P_ID_NACIONALIDAD:", P_ID_NACIONALIDAD);
  console.log("P_TIPO_CONTACTO:", P_TIPO_CONTACTO);
  console.log("P_CONTACTO:", P_CONTACTO);
  console.log("P_PARENTESCO:", P_PARENTESCO);
  console.log("P_CONDOMINIO:", P_CONDOMINIO);
  console.log("----------------------------------------------------");
  // Validación básica de campos requeridos
  if (
    !usuarioId ||
    !P_ID_NACIONALIDAD ||
    !P_TIPO_CONTACTO ||
    !P_CONTACTO ||
    !P_PARENTESCO ||
    !P_CONDOMINIO
  ) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  // Validar que se tenga DNI o Carnet de Extranjero según la nacionalidad
  const esHondurena =
    P_ID_NACIONALIDAD && P_ID_NACIONALIDAD.toLowerCase().includes("hondureña");

  if (esHondurena && !P_DNI) {
    return res
      .status(400)
      .json({ error: "El DNI es requerido para nacionalidad hondureña" });
  }

  if (!esHondurena && !P_NUM_CARNET_EXTRANJERO) {
    return res.status(400).json({
      error:
        "El Carnet de Extranjero es requerido para nacionalidad extranjera",
    });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // ********* NUEVA VALIDACIÓN: Validar DNI hondureño *********
    if (esHondurena && P_DNI) {
      // Validar que el DNI tenga al menos 4 dígitos
      if (P_DNI.length < 13) {
        return res.status(400).json({
          error: "El número de identidad debe tener al menos 13 dígitos",
        });
      }

      // Obtener los primeros 4 dígitos del DNI
      const codigoDNI = P_DNI.substring(0, 4);
      // Validar el código en la tabla TBL_CODIGO_DNI
      const [codigoResults] = await connection.query(
        "SELECT COUNT(*) as count FROM TBL_CODIGO_DNI WHERE CODIGO = ?",
        [codigoDNI]
      );

      if (codigoResults[0].count === 0) {
        return res.status(400).json({
          error:
            "El número de identidad ingresado no corresponde a un código válido. Por favor, verifique su DNI.",
        });
      }
    }

    // Obtener ID_CONDOMINIO y USUARIOS_POR_CASA desde la descripción
    const [condominioResults] = await connection.query(
      "SELECT ID_CONDOMINIO, USUARIOS_POR_CASA FROM TBL_CONDOMINIOS WHERE DESCRIPCION = ?",
      [P_CONDOMINIO]
    );

    if (condominioResults.length === 0) {
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
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener ID_PERSONA
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const ID_PERSONA = personaResults[0].ID_PERSONA;

    // ********* NUEVA LÓGICA: Obtener ID_NACIONALIDAD *********
    let ID_NACIONALIDAD = null;
    if (P_ID_NACIONALIDAD) {
      const [nacionalidadResults] = await connection.query(
        "SELECT ID_NACIONALIDAD FROM TBL_NACIONALIDADES WHERE NOMBRE_NACIONALIDAD = ?",
        [P_ID_NACIONALIDAD]
      );

      if (nacionalidadResults.length > 0) {
        ID_NACIONALIDAD = nacionalidadResults[0].ID_NACIONALIDAD;
      }
    }

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

    // ********* ACTUALIZAR PERSONA CON NUEVOS CAMPOS *********
    const queryParams = [
      P_DNI || null, // DNI (null si es extranjero)
      P_NUM_CARNET_EXTRANJERO || null, // Carnet de extranjero (null si es hondureño)
      ID_NACIONALIDAD, // ID de nacionalidad
      ID_CONTACTO,
      1, // ID_ESTADO_PERSONA
      ID_PARENTESCO,
      ID_CONDOMINIO,
      ID_PERSONA,
    ];

    const updatePersonaQuery = isAdminRequired
      ? `
      UPDATE TBL_PERSONAS
      SET DNI_PERSONA = ?, NUM_CARNET_EXTRANJERO = ?, ID_NACIONALIDAD = ?,
      ID_CONTACTO = ?, ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?,
      ID_CONDOMINIO = ?, ID_PADRE = 1
      WHERE ID_PERSONA = ?`
      : `
      UPDATE TBL_PERSONAS
      SET DNI_PERSONA = ?, NUM_CARNET_EXTRANJERO = ?, ID_NACIONALIDAD = ?,
      ID_CONTACTO = ?, ID_ESTADO_PERSONA = ?, ID_PARENTESCO = ?,
      ID_CONDOMINIO = ?, ID_PADRE = NULL
      WHERE ID_PERSONA = ?`;

    await connection.query(updatePersonaQuery, queryParams);

    // Marcar primer ingreso completado
    await connection.query(
      "UPDATE TBL_MS_USUARIO SET PRIMER_INGRESO_COMPLETADO = 1 WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    // Enviar correo si es el primer administrador global
    if (isAdminRequired) {
      const [adminEmails] = await mysqlPool.query(
        "SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4)"
      );

      const emailList = adminEmails.map((row) => row.EMAIL);

      const mailOptions = {
        from: "villalasacacias@villalasacacias.com",
        to: emailList,
        subject: "Registro de Nuevo Administrador de la vivienda",
        html: `
          <p>Estimados Administradores,</p>
          <p>Se ha registrado un nuevo administrador para la vivienda:</p>
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

      pushService.notificarRoles(mysqlPool, [1, 4], {
        titulo: "Nuevo Administrador de Vivienda",
        mensaje: `${nombreUsuario} se registró como titular de la vivienda ${P_CONDOMINIO}.`,
        tipo: "USUARIO",
        data: { ruta: "/residentes" },
      }).catch(() => {});
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
        // Determinar qué documento mostrar en el correo
        const documentoInfo = esHondurena
          ? `<p><strong>DNI:</strong> ${P_DNI}</p>`
          : `<p><strong>Carnet de Extranjero:</strong> ${P_NUM_CARNET_EXTRANJERO}</p>`;

        const mailOptionsAdmin = {
          from: "villalasacacias@villalasacacias.com",
          to: correos,
          subject: "Nuevo usuario registrado en la vivienda",
          html: `
            <p>Estimado(s) Administrador(es),</p>
            <p>Se ha registrado un nuevo usuario en la vivienda <strong>${P_CONDOMINIO}</strong>.</p>
            <p><strong>Nombre:</strong> ${nombreUsuario}</p>
            <p><strong>Nacionalidad:</strong> ${P_ID_NACIONALIDAD}</p>
            ${documentoInfo}
            <p><strong>Contacto:</strong> ${P_CONTACTO}</p>
            <p>Saludos cordiales,<br>Villas Las Acacias</p>
          `,
        };

        transporter.sendMail(mailOptionsAdmin, (err) => {
          if (err) {
            console.error(
              "Error al enviar correo a administradores de la vivienda:",
              err
            );
          } else {
            console.log(
              "Correo enviado a administradores de la vivienda:",
              correos
            );
          }
        });

        pushService.notificarAdminCondominio(mysqlPool, ID_CONDOMINIO, {
          titulo: "Nuevo miembro del hogar registrado",
          mensaje: `${nombreUsuario} se ha registrado en tu vivienda (${P_CONDOMINIO}) y espera tu aprobación.`,
          tipo: "FAMILIA",
          data: {
            ruta: "/solicitudes",
            idCondominio: ID_CONDOMINIO,
          },
        }).catch(() => {});
      } else {
        console.warn(
          "No se encontraron correos de administradores de la vivienda."
        );
      }
    } else {
      console.warn("No hay administradores registrados en la vivienda.");
    }

    res.status(201).json({
      success: true,
      message:
        "Persona actualizada correctamente y PRIMER_INGRESO_COMPLETADO establecido en 1",
    });
  } catch (err) {
    console.error("Error al procesar la solicitud:", err);
    res.status(500).json({ error: "Error al procesar la solicitud" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//********** Actualizar lo PRIMER_INGRESO_COMPLETADO ********
app.put("/desactivarPersona", async (req, res) => {
  const { ID_USUARIO } = req.body;

  if (!ID_USUARIO) {
    return res.status(400).json({ error: "ID_USUARIO es requerido" });
  }

  const updateQuery =
    "UPDATE TBL_MS_USUARIO SET PRIMER_INGRESO_COMPLETADO = 1 WHERE ID_USUARIO = ?";
  let connection;

  try {
    connection = await mysqlPool.getConnection();
    const [result] = await connection.query(updateQuery, [ID_USUARIO]);

    if (result.affectedRows > 0) {
      res.status(200).json({
        success: true,
        message: "PRIMER_INGRESO_COMPLETADO actualizado correctamente",
      });
    } else {
      res.status(404).json({
        error: "No se encontró el usuario con el ID_USUARIO proporcionado",
      });
    }
  } catch (err) {
    console.error("Error al actualizar PRIMER_INGRESO_COMPLETADO:", err);
    res
      .status(500)
      .json({ error: "Error al actualizar PRIMER_INGRESO_COMPLETADO" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//Identificar el ID_PADRE del residente y mostrarle las solicitudes
app.get("/solicitudes", async (req, res) => {
  const usuarioId = req.query.usuario_id;
  //const {usuarioId}= req.body;
  console.log(usuarioId);

  if (!usuarioId) {
    return res.status(400).json({ error: "Se requiere usuario_id" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection(); // Obtener conexión del pool

    // Obtener el nombre de usuario
    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    // Obtener el ID_PERSONA usando el nombreUsuario
    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, ID_PADRE, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ message: "Persona no encontrada" });
    }

    const { ID_PERSONA, ID_PADRE, ID_CONDOMINIO } = personaResults[0];

    // Verificar si el usuario es administrador (ID_PADRE debe ser 1)
    if (ID_PADRE !== 1) {
      return res
        .status(403)
        .json({ message: "No tienes los permisos para poder ingresar" });
    }

    // Obtener todos los nombres en ese ID_CONDOMINIO que tengan el estado pendiente (ID_ESTADO_USUARIO = 5)
    const [residentesResults] = await connection.query(
      `SELECT 
              p.NOMBRE_PERSONA, 
              p.DNI_PERSONA, 
              p.NUM_CARNET_EXTRANJERO,
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

    if (residentesResults.length === 0) {
      return res
        .status(200)
        .json({ message: "No hay residentes pendientes de aprobación" });
    }

    res.status(200).json({ residentesPendientes: residentesResults });
  } catch (err) {
    console.error("Error al obtener las solicitudes de residentes:", err);
    res
      .status(500)
      .json({ error: "Error al obtener las solicitudes de residentes" });
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//***** Acepta las solicitudes solo el que es ID_PADRE
app.post("/aceptar", async (req, res) => {
  const { idUsuario } = req.body;

  if (!idUsuario) {
    return res.status(400).json({ error: "Se requiere idUsuario" });
  }

  console.log("Datos recibidos en /aceptar:", req.body);
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    await mysqlPool.query(
      "UPDATE TBL_MS_USUARIO SET ID_ESTADO_USUARIO = 1 WHERE ID_USUARIO = ?",
      [idUsuario]
    );

    pushService.notificarUsuario(mysqlPool, idUsuario, {
      titulo: "¡Registro Aprobado!",
      mensaje: "El administrador de tu vivienda ha aprobado tu registro en Villa Las Acacias.",
      tipo: "FAMILIA",
      data: { ruta: "/pantalla_principal" },
    }).catch(() => {});

    res.status(200).send("Solicitud aceptada");
  } catch (err) {
    console.error("Error al aceptar la solicitud:", err);
    res.status(500).send("Error al aceptar la solicitud");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//***** Rechaza las solicitudes solo el que es ID_PADRE
app.post("/rechazar", async (req, res) => {
  const { idUsuario } = req.body;

  if (!idUsuario) {
    return res.status(400).json({ error: "Se requiere idUsuario" });
  }

  console.log("Datos recibidos en /rechazar:", req.body);

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    // Iniciar la transacción
    await connection.beginTransaction();

    // Obtener el NOMBRE_USUARIO y EMAIL asociado al ID_USUARIO
    const [userResult] = await connection.query(
      "SELECT NOMBRE_USUARIO, EMAIL FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [idUsuario]
    );

    if (userResult.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const { NOMBRE_USUARIO: nombreUsuario, EMAIL: email } = userResult[0];

    pushService.notificarUsuario(mysqlPool, idUsuario, {
      titulo: "Solicitud Rechazada",
      mensaje: "Tu solicitud de registro para la vivienda ha sido rechazada.",
      tipo: "FAMILIA",
      data: { ruta: "/login" },
    }).catch(() => {});

    // Eliminar el registro de TBL_PERSONAS basado en el NOMBRE_USUARIO
    await connection.query(
      "DELETE FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    // Eliminar el registro de TBL_MS_USUARIO basado en el ID_USUARIO
    await connection.query("DELETE FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?", [
      idUsuario,
    ]);

    // Confirmar la transacción
    await connection.commit();

    // Configurar el correo electrónico
    const mailOptions = {
      from: "villalasacacias@villalasacacias.com",
      to: email,
      subject: "Solicitud Rechazada",
      html: `
              <p>Estimad@ ${nombreUsuario},</p>
              <p>Lamentamos informarle que su solicitud ha sido rechazada en Villa Las Acacias.</p>
              <p>Si tiene alguna pregunta o necesita más información, no dude en ponerse en contacto con la administración.</p>
              <p>Atentamente,</p>
              <p>El equipo de administración de Villas Las Acacias</p>
          `,
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error("Error al enviar el correo:", err);
        return res.status(500).json({ error: "Error al enviar el correo" });
      }
      console.log("Correo enviado a:", email);
    });

    res.status(200).send("Solicitud rechazada y correo enviado correctamente");
  } catch (err) {
    // Revertir los cambios en caso de error
    await connection.rollback();
    console.error("Error al rechazar la solicitud:", err);
    res.status(500).send("Error al rechazar la solicitud");
  } finally {
    if (connection) {
      console.log("Conexion liberada");
      connection.release();
    }
  }
});

//Confirmar las visitas del QR
app.post("/confirmar_visita", async (req, res) => {
  console.log("Datos recibidos:", req.body);
  const { nombreResidente, nombreVisitante, numeroPersonas } = req.body;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [rows] = await connection.query(
      `SELECT u.EMAIL 
       FROM TBL_MS_USUARIO u
       LEFT JOIN TBL_PERSONAS p ON (p.ID_PERSONA = u.ID_PERSONA OR u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci)
       WHERE u.NOMBRE_USUARIO = ? OR p.NOMBRE_PERSONA = ?
       LIMIT 1`,
      [nombreResidente, nombreResidente]
    );

    if (rows.length > 0 && rows[0].EMAIL) {
      const emailResidente = rows[0].EMAIL;
      const fechaActual = moment
        .tz("America/Tegucigalpa")
        .format("DD-MM-YYYY HH:mm");

      const mailOptions = {
        from: "villalasacacias@villalasacacias.com",
        to: emailResidente,
        subject: "Confirmación de Visita",
        html: `
                <p>Estimado ${nombreResidente},</p>
                <p>Le informamos que ha llegado un visitante:</p>
                <p><strong>Nombre del visitante:</strong> ${nombreVisitante}</p>
                <p><strong>Número de personas:</strong> ${numeroPersonas}</p>
                <p><strong>Fecha y hora de llegada:</strong> ${fechaActual}</p>
                <p>Atentamente,</p>
                <p>El equipo de administración de Villas Las Acacias</p>
            `,
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) console.error("Error al enviar correo de visita:", err);
      });
    }

    return res.status(200).json({ message: "Visita confirmada exitosamente" });
  } catch (err) {
    console.error("Error al realizar la operación:", err);
    return res.status(500).json({ error: "Error al procesar la solicitud" });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// Ruta para enviar correos del comportamiento de los visitantes
app.post("/notificarMotivo", async (req, res) => {
  const {
    nombreResidente,
    dniResidente,
    carnetExtranjeroResidente,
    contacto,
    condominio,
    nombreVisitante,
    dniVisitante,
    carnetExtranjeroVisitante,
    numeroPersonas,
    motivo,
    nacionalidadVisitante,
    nacionalidadResidente,
  } = req.body;

  // 1. Validaciones básicas
  if (!nombreResidente || !nombreVisitante || !motivo) {
    return res.status(400).json({ error: "Datos requeridos faltantes" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    // 2. Obtener correos de administradores y del residente
    const [adminEmailsResult] = await connection.query(
      "SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4)"
    );
    const adminEmails = adminEmailsResult.map((row) => row.EMAIL);

    const [residentEmailResult] = await connection.query(
      "SELECT EMAIL FROM TBL_MS_USUARIO WHERE NOMBRE_USUARIO = ?",
      [nombreResidente]
    );

    const residentEmail = residentEmailResult.length
      ? residentEmailResult[0].EMAIL
      : null;

    if (!residentEmail) {
      return res
        .status(404)
        .json({ error: "No se encontró el correo del residente" });
    }

    // 3. Determinar el documento del residente y del visitante
    const esResidenteHondureno =
      nacionalidadResidente &&
      nacionalidadResidente.toLowerCase().includes("hondureña");
    const docResidente = esResidenteHondureno
      ? `DNI: ${dniResidente || "No disponible"}`
      : `Carnet Extranjero: ${carnetExtranjeroResidente || "No disponible"}`;

    const esVisitanteHondureno =
      nacionalidadVisitante &&
      nacionalidadVisitante.toLowerCase().includes("hondureña");
    const docVisitante = esVisitanteHondureno
      ? `DNI: ${dniVisitante || "No disponible"}`
      : `Carnet Extranjero: ${carnetExtranjeroVisitante || "No disponible"}`;

    const fechaActual = moment
      .tz("America/Tegucigalpa")
      .format("DD-MM-YYYY HH:mm");

    // 4. Crear el contenido del correo dinámico
    const emailContent = `
      <p>Estimados Administradores y Residente,</p>
      <p>Por este medio les notificamos sobre un incidente relacionado con el comportamiento de una visita:</p>
      <p><strong>Motivo:</strong> ${motivo}</p>
      <p><strong>Fecha y hora:</strong> ${fechaActual}</p>
      <p><strong>Detalles del Visitante:</strong></p>
      <ul>
        <li><strong>Nombre:</strong> ${nombreVisitante}</li>
        <li><strong>Nacionalidad:</strong> ${
          nacionalidadVisitante || "No disponible"
        }</li>
        <li><strong>Documento:</strong> ${docVisitante}</li>
        <li><strong>Número de personas:</strong> ${numeroPersonas}</li>
      </ul>
      <p><strong>Detalles del Residente Asociado:</strong></p>
      <ul>
        <li><strong>Nombre:</strong> ${nombreResidente}</li>
        <li><strong>Documento:</strong> ${docResidente}</li>
        <li><strong>Contacto:</strong> ${contacto}</li>
        <li><strong>Numero de casa:</strong> ${condominio}</li>
      </ul>
      <p>Les solicitamos su colaboración para resolver esta situación y tomar las medidas necesarias para evitar incidentes futuros.</p>
      <p>Atentamente,</p>
      <p>El equipo de administración de Villas Las Acacias</p>
    `;

    // 5. Opciones de envío y envío del correo
    const mailOptions = {
      from: "villalasacacias@villalasacacias.com",
      to: [...adminEmails, residentEmail],
      subject: "Comportamiento de Visita",
      html: emailContent,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error("Error al enviar el correo:", err);
        return res.status(500).json({ error: "Error al enviar el correo" });
      }
      console.log("Correo enviado a:", [...adminEmails, residentEmail]);
      res.status(200).json({ message: "Correo enviado exitosamente" });
    });
  } catch (error) {
    console.error("Error al procesar la solicitud:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  } finally {
    if (connection) {
      console.log("Conexión liberada");
      connection.release();
    }
  }
});

// Actualizar fecha de vencimiento de visita recurrente
app.post("/actualizarVencimientoRecurrente", async (req, res) => {
  const { ID_VISITANTE, FECHA_VENCIMIENTO, NUM_PERSONAS, NUM_PLACA } = req.body;
  if (!ID_VISITANTE || !FECHA_VENCIMIENTO) {
    return res.status(400).json({ message: "ID_VISITANTE y FECHA_VENCIMIENTO son requeridos" });
  }

  const fechaVencimientoFormateada = moment(FECHA_VENCIMIENTO, "DD-MM-YYYY HH:mm").format("YYYY-MM-DD HH:mm:ss");

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    await connection.query(
      "UPDATE TBL_VISITANTES_RECURRENTES SET FECHA_VENCIMIENTO = ?, NUM_PERSONAS = ?, NUM_PLACA = ? WHERE ID_VISITANTES_RECURRENTES = ?",
      [fechaVencimientoFormateada, NUM_PERSONAS, NUM_PLACA, ID_VISITANTE]
    );

    await connection.query(
      "UPDATE TBL_BITACORA_VISITA SET FECHA_VENCIMIENTO = ?, NUM_PERSONA = ?, NUM_PLACA = ? WHERE ID_VISITANTES_RECURRENTES = ?",
      [fechaVencimientoFormateada, NUM_PERSONAS, NUM_PLACA, ID_VISITANTE]
    );

    await connection.commit();
    res.status(200).json({ message: "Visita recurrente actualizada correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al actualizar vencimiento:", error);
    res.status(500).json({ error: "Error en el servidor" });
  } finally {
    if (connection) connection.release();
  }
});

// Convertir una visita única ("No recurrente") a "Recurrente"
app.post("/convertirARecurrente", async (req, res) => {
  const { ID_VISITANTE, FECHA_VENCIMIENTO, NUM_PERSONAS, NUM_PLACA } = req.body;
  if (!ID_VISITANTE || !FECHA_VENCIMIENTO) {
    return res.status(400).json({ message: "ID_VISITANTE y FECHA_VENCIMIENTO son requeridos" });
  }

  const fechaVencimientoFormateada = moment(FECHA_VENCIMIENTO, "DD-MM-YYYY HH:mm").format("YYYY-MM-DD HH:mm:ss");

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    // 1. Obtener datos de la visita original
    const [visita] = await connection.query(
      "SELECT * FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?",
      [ID_VISITANTE]
    );

    if (visita.length === 0) {
      return res.status(404).json({ error: "Visita no encontrada" });
    }

    const v = visita[0];

    // 2. Insertar en TBL_VISITANTES_RECURRENTES
    const [insertResult] = await connection.query(
      "INSERT INTO TBL_VISITANTES_RECURRENTES (ID_PERSONA, NOMBRE_VISITANTE, ID_NACIONALIDAD, DNI_VISITANTE, NUM_CARNET_EXTRANJERO, NUM_PERSONAS, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [v.ID_PERSONA, v.NOMBRE_VISITANTE, v.ID_NACIONALIDAD, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, NUM_PERSONAS || v.NUM_PERSONAS, NUM_PLACA || v.NUM_PLACA, v.FECHA_HORA, fechaVencimientoFormateada]
    );

    const ID_RECURRENTE = insertResult.insertId;

    // 3. Actualizar Bitácora
    await connection.query(
      "UPDATE TBL_BITACORA_VISITA SET ID_VISITANTE = NULL, ID_VISITANTES_RECURRENTES = ?, FECHA_VENCIMIENTO = ?, NUM_PERSONA = ?, NUM_PLACA = ? WHERE ID_VISITANTE = ?",
      [ID_RECURRENTE, fechaVencimientoFormateada, NUM_PERSONAS || v.NUM_PERSONAS, NUM_PLACA || v.NUM_PLACA, ID_VISITANTE]
    );

    // 4. Eliminar de TBL_REGVISITAS
    await connection.query(
      "DELETE FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?",
      [ID_VISITANTE]
    );

    await connection.commit();
    res.status(200).json({ message: "Visita convertida a recurrente exitosamente", ID_RECURRENTE });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al convertir a recurrente:", error);
    res.status(500).json({ error: "Error en el servidor" });
  } finally {
    if (connection) connection.release();
  }
});

// Obtener QR para una visita existente
app.get("/obtenerQRVisita", async (req, res) => {
  const { idVisitante, tipo } = req.query;
  if (!idVisitante || !tipo) {
    return res.status(400).json({ error: "idVisitante y tipo son requeridos" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    let query, idPersona;

    if (tipo === "Recurrente") {
      query = "SELECT * FROM TBL_VISITANTES_RECURRENTES WHERE ID_VISITANTES_RECURRENTES = ?";
    } else {
      query = "SELECT * FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?";
    }

    const [visitaRows] = await connection.query(query, [idVisitante]);
    if (visitaRows.length === 0) {
      return res.status(404).json({ error: "Visita no encontrada" });
    }

    const v = visitaRows[0];
    idPersona = v.ID_PERSONA;

    // Obtener info del residente
    const [personaInfoResults] = await connection.query(
      `SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, p.NUM_CARNET_EXTRANJERO, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
       FROM TBL_PERSONAS p
       LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
       LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
       WHERE p.ID_PERSONA = ?`,
      [idPersona]
    );

    if (personaInfoResults.length === 0) {
      return res.status(404).json({ message: "Información del residente no encontrada" });
    }

    const p = personaInfoResults[0];
    
    // Obtener nacionalidad string
    const [nac] = await connection.query("SELECT NOMBRE_NACIONALIDAD FROM TBL_NACIONALIDADES WHERE ID_NACIONALIDAD = ?", [v.ID_NACIONALIDAD]);
    const nacionalidadStr = nac.length > 0 ? nac[0].NOMBRE_NACIONALIDAD : "N/A";

    let qrData;
    if (tipo === "Recurrente") {
      qrData = {
        Residente: p.NOMBRE_PERSONA,
        DNI_Residente: p.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: p.NUM_CARNET_EXTRANJERO,
        Contacto: p.CONTACTO,
        ID_VISITANTE: Number(idVisitante),
        Condominio: p.ID_CONDOMINIO,
        NOMBRE_VISITANTE: v.NOMBRE_VISITANTE,
        NACIONALIDAD: nacionalidadStr,
        DNI_VISITANTE: v.DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: v.NUM_CARNET_EXTRANJERO,
        NUM_PERSONAS: v.NUM_PERSONAS,
        NUM_PLACA: v.NUM_PLACA,
        FECHA_VENCIMIENTO: moment(v.FECHA_VENCIMIENTO).format("YYYY-MM-DD HH:mm:ss"),
        ID_CONDOMINIO: p.ID_CONDOMINIO,
      };
    } else {
       // Para no recurrentes, buscar la fecha calculada originalmente en bitacora
       const [bitacora] = await connection.query("SELECT FECHA_VENCIMIENTO FROM TBL_BITACORA_VISITA WHERE ID_VISITANTE = ?", [idVisitante]);
       const fechaVence = bitacora.length > 0 ? moment(bitacora[0].FECHA_VENCIMIENTO).format("YYYY-MM-DD HH:mm:ss") : moment(v.FECHA_HORA).add(24, 'hours').format("YYYY-MM-DD HH:mm:ss");

       qrData = {
        Residente: p.NOMBRE_PERSONA,
        DNI_Residente: p.DNI_PERSONA,
        NUM_CARNET_EXTRANJERO_Residente: p.NUM_CARNET_EXTRANJERO,
        Contacto: p.CONTACTO,
        ID_VISITANTE: Number(idVisitante),
        Condominio: p.ID_CONDOMINIO,
        NOMBRE_VISITANTE: v.NOMBRE_VISITANTE,
        NACIONALIDAD: nacionalidadStr,
        DNI_VISITANTE: v.DNI_VISITANTE,
        NUM_CARNET_EXTRANJERO: v.NUM_CARNET_EXTRANJERO,
        NUM_PERSONAS: v.NUM_PERSONAS,
        NUM_PLACA: v.NUM_PLACA,
        FECHA_HORA: fechaVence,
        ID_CONDOMINIO: p.ID_CONDOMINIO,
      };
    }

    const tokenQR = generarTokenSeguroQR(Number(idVisitante), tipo);

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    res.status(200).json({
      qrCode: qrUrl,
      qrData: qrData,
      qrToken: tokenQR,
    });
  } catch (error) {
    console.error("Error al generar QR:", error);
    res.status(500).json({ error: "Error en el servidor" });
  } finally {
    if (connection) connection.release();
  }
});

// Duplicar una visita puntual para la fecha actual
app.post("/duplicarVisitaPuntual", async (req, res) => {
  const { ID_VISITANTE, NUM_PERSONAS, NUM_PLACA } = req.body;
  if (!ID_VISITANTE) {
    return res.status(400).json({ error: "ID_VISITANTE es requerido" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    // 1. Obtener datos de la visita original
    const [visitaRows] = await connection.query(
      "SELECT * FROM TBL_REGVISITAS WHERE ID_VISITANTE = ?",
      [ID_VISITANTE]
    );

    if (visitaRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Visita original no encontrada" });
    }

    const v = visitaRows[0];

    // 2. Obtener parámetro de vencimiento
    const [parametroResults] = await connection.query(
      'SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = "QR_VENCIMIENTO"'
    );
    const horas = parametroResults.length > 0 ? parseInt(parametroResults[0].VALOR) : 24;
    
    const fechaActual = moment().tz("America/Tegucigalpa");
    const fechaActualStr = fechaActual.format("YYYY-MM-DD HH:mm:ss");
    const fechaVenceStr = fechaActual.clone().add(horas, "hours").format("YYYY-MM-DD HH:mm:ss");

    // Use provided values or original ones
    const finalNumPersons = NUM_PERSONAS || v.NUM_PERSONAS;
    const finalNumPlaca = NUM_PLACA || v.NUM_PLACA;

    // 3. Insertar nueva visita
    const [insertResult] = await connection.query(
      "INSERT INTO TBL_REGVISITAS (ID_PERSONA, NOMBRE_VISITANTE, ID_NACIONALIDAD, DNI_VISITANTE, NUM_CARNET_EXTRANJERO, NUM_PERSONAS, NUM_PLACA, FECHA_HORA) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [v.ID_PERSONA, v.NOMBRE_VISITANTE, v.ID_NACIONALIDAD, v.DNI_VISITANTE, v.NUM_CARNET_EXTRANJERO, finalNumPersons, finalNumPlaca, fechaActualStr]
    );

    const nuevoID = insertResult.insertId;

    // 4. Insertar en Bitácora
    await connection.query(
      "INSERT INTO TBL_BITACORA_VISITA (ID_PERSONA, ID_VISITANTE, NUM_PERSONA, NUM_PLACA, FECHA_HORA, FECHA_VENCIMIENTO) VALUES (?, ?, ?, ?, ?, ?)",
      [v.ID_PERSONA, nuevoID, finalNumPersons, finalNumPlaca, fechaActualStr, fechaVenceStr]
    );

    // 5. Preparar datos para el QR
    const [personaInfo] = await connection.query(
      `SELECT p.NOMBRE_PERSONA, p.DNI_PERSONA, p.NUM_CARNET_EXTRANJERO, c.DESCRIPCION AS CONTACTO, d.DESCRIPCION AS ID_CONDOMINIO
       FROM TBL_PERSONAS p
       LEFT JOIN TBL_CONTACTOS c ON p.ID_CONTACTO = c.ID_CONTACTO
       LEFT JOIN TBL_CONDOMINIOS d ON p.ID_CONDOMINIO = d.ID_CONDOMINIO
       WHERE p.ID_PERSONA = ?`,
      [v.ID_PERSONA]
    );

    const p = personaInfo[0];
    const [nac] = await connection.query("SELECT NOMBRE_NACIONALIDAD FROM TBL_NACIONALIDADES WHERE ID_NACIONALIDAD = ?", [v.ID_NACIONALIDAD]);
    const nacionalidadStr = nac.length > 0 ? nac[0].NOMBRE_NACIONALIDAD : "N/A";

    const qrData = {
      Residente: p.NOMBRE_PERSONA,
      DNI_Residente: p.DNI_PERSONA,
      NUM_CARNET_EXTRANJERO_Residente: p.NUM_CARNET_EXTRANJERO,
      Contacto: p.CONTACTO,
      ID_VISITANTE: nuevoID,
      Condominio: p.ID_CONDOMINIO,
      NOMBRE_VISITANTE: v.NOMBRE_VISITANTE,
      NACIONALIDAD: nacionalidadStr,
      DNI_VISITANTE: v.DNI_VISITANTE,
      NUM_CARNET_EXTRANJERO: v.NUM_CARNET_EXTRANJERO,
      NUM_PERSONAS: finalNumPersons,
      NUM_PLACA: finalNumPlaca,
      FECHA_HORA: fechaVenceStr,
      ID_CONDOMINIO: p.ID_CONDOMINIO,
    };

    const tokenQR = generarTokenSeguroQR(nuevoID, "Normal");

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    await connection.commit();
    res.status(200).json({
      message: "Nueva visita registrada exitosamente",
      qrCode: qrUrl,
      qrData: qrData,
      qrToken: tokenQR,
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al duplicar visita:", error);
    res.status(500).json({ error: "Error en el servidor" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/registrar_paquete", async (req, res) => {
  const {
    usuarioId,
    EMPRESA_REMITENTE,
    TIPO_REMITENTE,
    DIMENSION,
    DESCRIPCION,
    FECHA_ESTIMADA_ENTREGA,
  } = req.body;

  if (!usuarioId || !EMPRESA_REMITENTE || !DIMENSION || !FECHA_ESTIMADA_ENTREGA) {
    return res.status(400).json({ error: "Campos requeridos incompletos" });
  }

  const dimensionRaw = String(DIMENSION).trim().toLowerCase();
  const esPequeno = dimensionRaw.includes("peque");
  const esMediano = dimensionRaw.includes("median");
  if (!esPequeno && !esMediano) {
    return res.status(400).json({ error: "La dimensión debe ser Pequeño o Mediano" });
  }
  const dimensionVal = esPequeno ? "Pequeño" : "Mediano";

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    const [personaResults] = await connection.query(
      `SELECT p.ID_PERSONA, p.NOMBRE_PERSONA, p.ID_CONDOMINIO, c.DESCRIPCION AS CONDOMINIO
       FROM TBL_PERSONAS p
       LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
       WHERE p.NOMBRE_PERSONA = ?`,
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ error: "Persona asociada no encontrada" });
    }

    const persona = personaResults[0];
    const tipoRemitenteVal = TIPO_REMITENTE || "Mensajería";

    let fechaEstimadaFormatted;
    if (moment(FECHA_ESTIMADA_ENTREGA, "DD-MM-YYYY HH:mm", true).isValid()) {
      fechaEstimadaFormatted = moment(FECHA_ESTIMADA_ENTREGA, "DD-MM-YYYY HH:mm").format("YYYY-MM-DD HH:mm:ss");
    } else if (moment(FECHA_ESTIMADA_ENTREGA).isValid()) {
      fechaEstimadaFormatted = moment(FECHA_ESTIMADA_ENTREGA).format("YYYY-MM-DD HH:mm:ss");
    } else {
      fechaEstimadaFormatted = moment().tz("America/Tegucigalpa").add(1, "day").format("YYYY-MM-DD HH:mm:ss");
    }

    const insertSql = `
      INSERT INTO TBL_REG_PAQUETES (
        ID_PERSONA, EMPRESA_REMITENTE, TIPO_REMITENTE, DIMENSION, DESCRIPCION, FECHA_ESTIMADA_ENTREGA, ESTADO_PAQUETE
      ) VALUES (?, ?, ?, ?, ?, ?, 'Pendiente')
    `;

    const [insertResult] = await connection.query(insertSql, [
      persona.ID_PERSONA,
      EMPRESA_REMITENTE,
      tipoRemitenteVal,
      dimensionVal,
      DESCRIPCION || "",
      fechaEstimadaFormatted,
    ]);

    const idPaquete = insertResult.insertId;
    const tokenQR = generarTokenSeguroQR(idPaquete, "Paquete");

    await connection.query(
      "UPDATE TBL_REG_PAQUETES SET TOKEN_QR = ? WHERE ID_PAQUETE = ?",
      [tokenQR, idPaquete]
    );

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    const qrData = {
      ID_PAQUETE: idPaquete,
      Empresa: EMPRESA_REMITENTE,
      TipoRemitente: tipoRemitenteVal,
      Dimension: dimensionVal,
      Descripcion: DESCRIPCION || "",
      FechaEstimada: fechaEstimadaFormatted,
      Residente: persona.NOMBRE_PERSONA,
      Condominio: persona.CONDOMINIO || "N/A",
      Estado: "Pendiente",
    };

    res.status(201).json({
      message: "Paquete registrado exitosamente",
      idPaquete: idPaquete,
      qrCode: qrUrl,
      qrToken: tokenQR,
      qrData: qrData,
    });
  } catch (error) {
    console.error("Error al registrar paquete:", error);
    res.status(500).json({ error: "Error en el servidor al registrar paquete" });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/consultar_paquetes", async (req, res) => {
  const usuarioId = req.query.usuarioId;
  const showAll = req.query.all === "true";

  if (!usuarioId) {
    return res.status(400).json({ error: "El usuarioId es requerido" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, ID_CONDOMINIO FROM TBL_PERSONAS WHERE NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const idPersona = personaResults[0].ID_PERSONA;
    const idCondominio = personaResults[0].ID_CONDOMINIO;

    let selectSql = `
      SELECT p.*, per.NOMBRE_PERSONA AS RESIDENTE, c.DESCRIPCION AS CONDOMINIO
      FROM TBL_REG_PAQUETES p
      JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
      LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
    `;
    let selectParams = [];

    if (showAll && idCondominio) {
      selectSql += " WHERE per.ID_CONDOMINIO = ? ORDER BY p.ID_PAQUETE DESC";
      selectParams.push(idCondominio);
    } else {
      selectSql += " WHERE p.ID_PERSONA = ? ORDER BY p.ID_PAQUETE DESC";
      selectParams.push(idPersona);
    }

    const [paquetes] = await connection.query(selectSql, selectParams);

    const paquetesConQR = await Promise.all(
      paquetes.map(async (paquete) => {
        let qrUrl = null;
        let tokenQR = paquete.TOKEN_QR;

        if (!tokenQR) {
          tokenQR = generarTokenSeguroQR(paquete.ID_PAQUETE, "Paquete");
          await connection.query(
            "UPDATE TBL_REG_PAQUETES SET TOKEN_QR = ? WHERE ID_PAQUETE = ?",
            [tokenQR, paquete.ID_PAQUETE]
          );
        }

        try {
          qrUrl = await new Promise((resolve, reject) => {
            QRCode.toDataURL(tokenQR, (err, url) => {
              if (err) return reject(err);
              resolve(url);
            });
          });
        } catch (e) {
          qrUrl = null;
        }

        const qrData = {
          ID_PAQUETE: paquete.ID_PAQUETE,
          Empresa: paquete.EMPRESA_REMITENTE,
          TipoRemitente: paquete.TIPO_REMITENTE,
          Dimension: paquete.DIMENSION,
          Descripcion: paquete.DESCRIPCION || "",
          FechaEstimada: paquete.FECHA_ESTIMADA_ENTREGA,
          Residente: paquete.RESIDENTE,
          Condominio: paquete.CONDOMINIO || "N/A",
          Estado: paquete.ESTADO_PAQUETE,
          EstadoFisico: paquete.ESTADO_FISICO,
          Observaciones: paquete.OBSERVACIONES_GUARDIA,
          FechaRecepcion: paquete.FECHA_RECEPCION,
        };

        return {
          ...paquete,
          qrCode: qrUrl,
          qrToken: tokenQR,
          qrData: qrData,
        };
      })
    );

    res.status(200).json(paquetesConQR);
  } catch (error) {
    console.error("Error al consultar paquetes:", error);
    res.status(500).json({ error: "Error en el servidor al consultar paquetes" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/actualizar_paquete", async (req, res) => {
  const {
    ID_PAQUETE,
    EMPRESA_REMITENTE,
    TIPO_REMITENTE,
    DIMENSION,
    DESCRIPCION,
    FECHA_ESTIMADA_ENTREGA,
  } = req.body;

  if (!ID_PAQUETE) {
    return res.status(400).json({ error: "ID_PAQUETE es requerido" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [rows] = await connection.query(
      `SELECT p.*, per.NOMBRE_PERSONA, c.DESCRIPCION AS CONDOMINIO
       FROM TBL_REG_PAQUETES p
       JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
       WHERE p.ID_PAQUETE = ?`,
      [ID_PAQUETE]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Paquete no encontrado" });
    }

    const paquete = rows[0];
    if (paquete.ESTADO_PAQUETE !== "Pendiente") {
      return res.status(400).json({ error: "Solo se pueden modificar paquetes en estado Pendiente" });
    }

    const nuevaEmpresa = EMPRESA_REMITENTE || paquete.EMPRESA_REMITENTE;
    const nuevoTipo = TIPO_REMITENTE || paquete.TIPO_REMITENTE;
    const nuevaDimension = DIMENSION || paquete.DIMENSION;
    const nuevaDescripcion = DESCRIPCION !== undefined ? DESCRIPCION : paquete.DESCRIPCION;

    let nuevaFecha;
    if (FECHA_ESTIMADA_ENTREGA) {
      if (moment(FECHA_ESTIMADA_ENTREGA, "DD-MM-YYYY HH:mm", true).isValid()) {
        nuevaFecha = moment(FECHA_ESTIMADA_ENTREGA, "DD-MM-YYYY HH:mm").format("YYYY-MM-DD HH:mm:ss");
      } else if (moment(FECHA_ESTIMADA_ENTREGA).isValid()) {
        nuevaFecha = moment(FECHA_ESTIMADA_ENTREGA).format("YYYY-MM-DD HH:mm:ss");
      } else {
        nuevaFecha = paquete.FECHA_ESTIMADA_ENTREGA;
      }
    } else {
      nuevaFecha = paquete.FECHA_ESTIMADA_ENTREGA;
    }

    const tokenQR = generarTokenSeguroQR(ID_PAQUETE, "Paquete");

    await connection.query(
      `UPDATE TBL_REG_PAQUETES SET
        EMPRESA_REMITENTE = ?,
        TIPO_REMITENTE = ?,
        DIMENSION = ?,
        DESCRIPCION = ?,
        FECHA_ESTIMADA_ENTREGA = ?,
        TOKEN_QR = ?
       WHERE ID_PAQUETE = ?`,
      [nuevaEmpresa, nuevoTipo, nuevaDimension, nuevaDescripcion, nuevaFecha, tokenQR, ID_PAQUETE]
    );

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    const qrData = {
      ID_PAQUETE: ID_PAQUETE,
      Empresa: nuevaEmpresa,
      TipoRemitente: nuevoTipo,
      Dimension: nuevaDimension,
      Descripcion: nuevaDescripcion,
      FechaEstimada: nuevaFecha,
      Residente: paquete.NOMBRE_PERSONA,
      Condominio: paquete.CONDOMINIO || "N/A",
      Estado: "Pendiente",
    };

    res.status(200).json({
      message: "Paquete actualizado exitosamente",
      qrCode: qrUrl,
      qrToken: tokenQR,
      qrData: qrData,
    });
  } catch (error) {
    console.error("Error al actualizar paquete:", error);
    res.status(500).json({ error: "Error en el servidor al actualizar paquete" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/validar_paquete_qr", async (req, res) => {
  const { token, idPaquete } = req.body;

  let idBuscado = null;

  if (token) {
    if (typeof token === "string" && token.startsWith("VLA_SEC_")) {
      const descifrado = descifrarTokenSeguroQR(token);
      if (descifrado && descifrado.id) {
        idBuscado = descifrado.id;
      }
    } else if (!isNaN(Number(token))) {
      idBuscado = Number(token);
    }
  } else if (idPaquete) {
    idBuscado = Number(idPaquete);
  }

  if (!idBuscado) {
    return res.status(400).json({ error: "Código QR o token no reconocido" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [rows] = await connection.query(
      `SELECT p.*, per.NOMBRE_PERSONA AS RESIDENTE, per.DNI_PERSONA,
              c.DESCRIPCION AS CONDOMINIO, u.EMAIL AS EMAIL_RESIDENTE
       FROM TBL_REG_PAQUETES p
       JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
       LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = per.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE p.ID_PAQUETE = ?`,
      [idBuscado]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Paquete no encontrado en el sistema" });
    }

    const p = rows[0];

    res.status(200).json({
      valido: true,
      paquete: {
        ID_PAQUETE: p.ID_PAQUETE,
        EMPRESA_REMITENTE: p.EMPRESA_REMITENTE,
        TIPO_REMITENTE: p.TIPO_REMITENTE,
        DIMENSION: p.DIMENSION,
        DESCRIPCION: p.DESCRIPCION,
        FECHA_ESTIMADA_ENTREGA: p.FECHA_ESTIMADA_ENTREGA,
        ESTADO_PAQUETE: p.ESTADO_PAQUETE,
        ESTADO_FISICO: p.ESTADO_FISICO,
        OBSERVACIONES_GUARDIA: p.OBSERVACIONES_GUARDIA,
        FECHA_RECEPCION: p.FECHA_RECEPCION,
        USUARIO_RECEPCION: p.USUARIO_RECEPCION,
        RESIDENTE: p.RESIDENTE,
        CONDOMINIO: p.CONDOMINIO,
        DNI_PERSONA: p.DNI_PERSONA,
        EMAIL_RESIDENTE: p.EMAIL_RESIDENTE,
      },
      puedeRecibir: p.ESTADO_PAQUETE === "Pendiente",
    });
  } catch (error) {
    console.error("Error al validar QR de paquete:", error);
    res.status(500).json({ error: "Error en el servidor al validar QR de paquete" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/recibir_paquete", async (req, res) => {
  const {
    ID_PAQUETE,
    ESTADO_FISICO,
    OBSERVACIONES_GUARDIA,
    USUARIO_RECEPCION,
    ESTADO_PAQUETE,
  } = req.body;

  if (!ID_PAQUETE) {
    return res.status(400).json({ error: "ID_PAQUETE es requerido" });
  }

  const estadoFinal = ESTADO_PAQUETE === "Rechazado" ? "Rechazado" : "Recibido";
  const estadoFisicoVal = ESTADO_FISICO || "Intacto";
  const observacionesVal = OBSERVACIONES_GUARDIA || "";
  const usuarioRecepcionVal = USUARIO_RECEPCION || "Guardia de Caseta";

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [rows] = await connection.query(
      `SELECT p.*, per.NOMBRE_PERSONA, per.ID_CONDOMINIO, c.DESCRIPCION AS CONDOMINIO, u.EMAIL AS EMAIL_RESIDENTE, u.ID_USUARIO
       FROM TBL_REG_PAQUETES p
       JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
       LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = per.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE p.ID_PAQUETE = ?`,
      [ID_PAQUETE]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Paquete no encontrado" });
    }

    const paquete = rows[0];
    const fechaRecepcion = moment().tz("America/Tegucigalpa").format("YYYY-MM-DD HH:mm:ss");

    await connection.query(
      `UPDATE TBL_REG_PAQUETES SET
        ESTADO_PAQUETE = ?,
        ESTADO_FISICO = ?,
        OBSERVACIONES_GUARDIA = ?,
        FECHA_RECEPCION = ?,
        USUARIO_RECEPCION = ?
       WHERE ID_PAQUETE = ?`,
      [estadoFinal, estadoFisicoVal, observacionesVal, fechaRecepcion, usuarioRecepcionVal, ID_PAQUETE]
    );

    const emailDestino = paquete.EMAIL_RESIDENTE;
    if (emailDestino) {
      try {
        const esRechazado = estadoFinal === "Rechazado";
        const asunto = esRechazado
          ? "Villa Las Acacias - Notificación: Paquete Rechazado en Caseta"
          : "Villa Las Acacias - Notificación: Paquete Recibido en Caseta";

        const contenidoHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
            <div style="background-color: ${esRechazado ? "#d32f2f" : "#14A13B"}; color: white; padding: 20px; text-align: center;">
              <h2 style="margin: 0;">Villa Las Acacias</h2>
              <p style="margin: 5px 0 0 0; font-size: 14px;">Control de Seguridad y Acceso</p>
            </div>
            <div style="padding: 24px; background-color: #ffffff;">
              <h3 style="color: #333333; margin-top: 0;">Estimado(a) ${paquete.NOMBRE_PERSONA},</h3>
              <p style="color: #555555; line-height: 1.5;">
                Le notificamos que se ha registrado la llegada de un paquete en la caseta de seguridad con los siguientes datos:
              </p>
              <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Empresa / Remitente:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333;">${paquete.EMPRESA_REMITENTE}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Dimensión:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333;">${paquete.DIMENSION}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Casa / Condominio:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333;">${paquete.CONDOMINIO || "N/A"}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Estado:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: ${esRechazado ? "#d32f2f" : "#14A13B"}; font-weight: bold;">${estadoFinal}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Condición física:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333; font-weight: bold;">${estadoFisicoVal}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Observaciones:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333;">${observacionesVal || "Sin observaciones adicionales"}</td>
                </tr>
                <tr>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555;">Fecha y hora de registro:</td>
                  <td style="padding: 8px; border-bottom: 1px solid #eeeeee; color: #333;">${fechaRecepcion}</td>
                </tr>
              </table>
              <p style="color: #666666; font-size: 13px; line-height: 1.4;">
                ${esRechazado
                  ? "El paquete no fue recibido debido a las observaciones señaladas. Por favor consulte en caseta para más detalles."
                  : "Puede retirar su paquete en la caseta de seguridad con el personal de guardia."}
              </p>
            </div>
            <div style="background-color: #f7f7f7; color: #888888; padding: 12px; text-align: center; font-size: 12px;">
              Villa Las Acacias &copy; ${new Date().getFullYear()}
            </div>
          </div>
        `;

        transporter.sendMail({
          from: '"Villa Las Acacias" <villalasacacias@villalasacacias.com>',
          to: emailDestino,
          subject: asunto,
          html: contenidoHtml,
        }, (mailError) => {
          if (mailError) console.error("Error al enviar correo de notificación paquete:", mailError);
        });
      } catch (mailError) {
        console.error("Error al preparar correo de notificación:", mailError);
      }
    }

    if (paquete.ID_USUARIO) {
      const tituloPush = estadoFinal === "Rechazado" ? "Paquete rechazado en caseta" : "Paquete recibido en caseta";
      const mensajePush = estadoFinal === "Rechazado"
        ? `Tu paquete de ${paquete.EMPRESA_REPARTIDORA || "mensajería"} fue rechazado en caseta.`
        : `Tu paquete de ${paquete.EMPRESA_REPARTIDORA || "mensajería"} ya está disponible en caseta.`;
      pushService.notificarUsuario(mysqlPool, paquete.ID_USUARIO, {
        titulo: tituloPush,
        mensaje: mensajePush,
        tipo: "PAQUETE",
        data: {
          ruta: "/paquetes",
          idPaquete: ID_PAQUETE
        }
      }).catch(err => console.error("Error push paquete usuario:", err));
    }

    if (paquete.ID_CONDOMINIO) {
      pushService.notificarAdminCondominio(mysqlPool, paquete.ID_CONDOMINIO, {
        titulo: estadoFinal === "Rechazado" ? "Paquete rechazado en caseta" : "Nuevo paquete en caseta",
        mensaje: `Paquete para ${paquete.NOMBRE_PERSONA} (${paquete.CONDOMINIO || ''}) registrado como ${estadoFinal}.`,
        tipo: "PAQUETE",
        data: {
          ruta: "/paquetes",
          idPaquete: ID_PAQUETE
        }
      }).catch(err => console.error("Error push paquete condominio:", err));
    }

    res.status(200).json({
      message: `Paquete registrado como ${estadoFinal} exitosamente`,
      paqueteId: ID_PAQUETE,
      estado: estadoFinal,
      fechaRecepcion: fechaRecepcion,
    });
  } catch (error) {
    console.error("Error al recibir paquete:", error);
    res.status(500).json({ error: "Error en el servidor al registrar recepción de paquete" });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/reporte_paquetes", async (req, res) => {
  const { condominio, fechaInicio, fechaFin, estado } = req.query;

  let connection;
  try {
    connection = await mysqlPool.getConnection();

    let querySql = `
      SELECT p.*, per.NOMBRE_PERSONA AS RESIDENTE, per.DNI_PERSONA,
             c.ID_CONDOMINIO, c.DESCRIPCION AS CONDOMINIO
      FROM TBL_REG_PAQUETES p
      JOIN TBL_PERSONAS per ON p.ID_PERSONA = per.ID_PERSONA
      LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
      WHERE 1=1
    `;
    const params = [];

    if (condominio) {
      querySql += " AND c.ID_CONDOMINIO = ?";
      params.push(condominio);
    }

    if (estado) {
      querySql += " AND p.ESTADO_PAQUETE = ?";
      params.push(estado);
    }

    if (fechaInicio) {
      querySql += " AND DATE(COALESCE(p.FECHA_RECEPCION, p.FECHA_ESTIMADA_ENTREGA)) >= ?";
      params.push(fechaInicio);
    }

    if (fechaFin) {
      querySql += " AND DATE(COALESCE(p.FECHA_RECEPCION, p.FECHA_ESTIMADA_ENTREGA)) <= ?";
      params.push(fechaFin);
    }

    querySql += " ORDER BY p.ID_PAQUETE DESC";

    const [rows] = await connection.query(querySql, params);
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener reporte de paquetes:", error);
    res.status(500).json({ error: "Error en el servidor al generar reporte de paquetes" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/registrar_visita_multiple", async (req, res) => {
  const {
    usuarioId,
    TITULO_EVENTO,
    OBSERVACIONES_RESIDENTE,
    FECHA_EVENTO,
    VISITANTES,
  } = req.body;

  if (!usuarioId || !TITULO_EVENTO || !FECHA_EVENTO || !Array.isArray(VISITANTES) || VISITANTES.length === 0) {
    return res.status(400).json({ error: "Datos requeridos incompletos o lista de visitantes vacía" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    const [personaResults] = await connection.query(
      "SELECT p.ID_PERSONA, p.NOMBRE_PERSONA, c.DESCRIPCION AS CONDOMINIO FROM TBL_PERSONAS p LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO WHERE p.NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const persona = personaResults[0];
    const ID_PERSONA = persona.ID_PERSONA;

    let fechaEventoObj;
    if (moment(FECHA_EVENTO, "DD-MM-YYYY HH:mm", true).isValid()) {
      fechaEventoObj = moment.tz(FECHA_EVENTO, "DD-MM-YYYY HH:mm", "America/Tegucigalpa");
    } else {
      fechaEventoObj = moment.tz(FECHA_EVENTO, "America/Tegucigalpa");
    }

    const fechaEventoStr = fechaEventoObj.format("YYYY-MM-DD HH:mm:ss");
    const fechaVencimientoStr = fechaEventoObj.clone().endOf("day").format("YYYY-MM-DD 23:59:59");
    const fechaCreacionStr = moment().tz("America/Tegucigalpa").format("YYYY-MM-DD HH:mm:ss");

    const [insertHeaderResult] = await connection.query(
      `INSERT INTO TBL_REG_VISITAS_MULTIPLES
       (ID_PERSONA, TITULO_EVENTO, OBSERVACIONES_RESIDENTE, FECHA_EVENTO, FECHA_VENCIMIENTO, ESTADO, FECHA_CREACION)
       VALUES (?, ?, ?, ?, ?, 'Activo', ?)`,
      [ID_PERSONA, TITULO_EVENTO.trim(), OBSERVACIONES_RESIDENTE ? OBSERVACIONES_RESIDENTE.trim() : null, fechaEventoStr, fechaVencimientoStr, fechaCreacionStr]
    );

    const ID_VISITA_MULTIPLE = insertHeaderResult.insertId;

    for (const v of VISITANTES) {
      const nombre = (v.nombre || v.NOMBRE_VISITANTE || "").toString().trim();
      const doc = v.documento || v.DOCUMENTO ? (v.documento || v.DOCUMENTO).toString().trim() : null;
      if (nombre.length > 0) {
        await connection.query(
          `INSERT INTO TBL_DETALLE_VISITAS_MULTIPLES
           (ID_VISITA_MULTIPLE, NOMBRE_VISITANTE, DOCUMENTO, ESTADO_INGRESO)
           VALUES (?, ?, ?, 'Pendiente')`,
          [ID_VISITA_MULTIPLE, nombre, doc]
        );
      }
    }

    const tokenQR = generarTokenSeguroQR(ID_VISITA_MULTIPLE, "Multiple");

    await connection.query(
      "UPDATE TBL_REG_VISITAS_MULTIPLES SET TOKEN_QR = ? WHERE ID_VISITA_MULTIPLE = ?",
      [tokenQR, ID_VISITA_MULTIPLE]
    );

    await connection.commit();

    const qrUrl = await new Promise((resolve, reject) => {
      QRCode.toDataURL(tokenQR, (err, url) => {
        if (err) return reject(err);
        resolve(url);
      });
    });

    const qrData = {
      ID_VISITA_MULTIPLE: ID_VISITA_MULTIPLE,
      TituloEvento: TITULO_EVENTO.trim(),
      ObservacionesResidente: OBSERVACIONES_RESIDENTE ? OBSERVACIONES_RESIDENTE.trim() : "",
      FechaEvento: moment(fechaEventoStr).tz("America/Tegucigalpa").format("DD/MM/YYYY hh:mm A"),
      FechaVencimiento: moment(fechaVencimientoStr).tz("America/Tegucigalpa").format("DD/MM/YYYY hh:mm A"),
      Residente: persona.NOMBRE_PERSONA,
      Condominio: persona.CONDOMINIO || "N/A",
      TotalInvitados: VISITANTES.length,
      Estado: "Activo",
    };

    res.status(201).json({
      message: "Visita múltiple registrada exitosamente",
      qrCode: qrUrl,
      qrToken: tokenQR,
      qrData: qrData,
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al registrar visita múltiple:", error);
    res.status(500).json({ error: "Error en el servidor al registrar visita múltiple" });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/mis_visitas_multiples/:usuarioId", async (req, res) => {
  const { usuarioId } = req.params;
  let connection;
  try {
    connection = await mysqlPool.getConnection();

    const [usuarioResults] = await connection.query(
      "SELECT NOMBRE_USUARIO FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );

    if (usuarioResults.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreUsuario = usuarioResults[0].NOMBRE_USUARIO;

    const [personaResults] = await connection.query(
      "SELECT ID_PERSONA, NOMBRE_PERSONA, c.DESCRIPCION AS CONDOMINIO FROM TBL_PERSONAS p LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO WHERE p.NOMBRE_PERSONA = ?",
      [nombreUsuario]
    );

    if (personaResults.length === 0) {
      return res.status(404).json({ error: "Persona no encontrada" });
    }

    const persona = personaResults[0];

    const [eventos] = await connection.query(
      `SELECT e.*, c.DESCRIPCION AS CONDOMINIO
       FROM TBL_REG_VISITAS_MULTIPLES e
       JOIN TBL_PERSONAS p ON e.ID_PERSONA = p.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
       WHERE e.ID_PERSONA = ?
       ORDER BY e.FECHA_EVENTO DESC`,
      [persona.ID_PERSONA]
    );

    const resultado = [];
    for (const ev of eventos) {
      const [visitantes] = await connection.query(
        `SELECT ID_DETALLE, ID_VISITA_MULTIPLE, NOMBRE_VISITANTE, DOCUMENTO, ESTADO_INGRESO, FECHA_INGRESO, OBSERVACIONES_GUARDIA, USUARIO_GUARDIA
         FROM TBL_DETALLE_VISITAS_MULTIPLES
         WHERE ID_VISITA_MULTIPLE = ?
         ORDER BY ID_DETALLE ASC`,
        [ev.ID_VISITA_MULTIPLE]
      );

      let qrUrl = null;
      if (ev.TOKEN_QR) {
        qrUrl = await new Promise((resolve) => {
          QRCode.toDataURL(ev.TOKEN_QR, (err, url) => {
            if (err) return resolve(null);
            resolve(url);
          });
        });
      }

      const fechaVencimientoObj = parseFechaTegucigalpa(ev.FECHA_VENCIMIENTO);
      const yaVencido = moment().tz("America/Tegucigalpa").isAfter(fechaVencimientoObj);
      const visitantesMapeados = visitantes.map((v) => {
        let estado = v.ESTADO_INGRESO || "Pendiente";
        if (ev.ESTADO === "Cancelado" && estado !== "Ingresado") {
          estado = "Cancelado";
        } else if (estado === "Pendiente" && yaVencido) {
          estado = "No se presentó";
        }
        return {
          ...v,
          ESTADO_INGRESO: estado,
        };
      });

      resultado.push({
        ID_VISITA_MULTIPLE: ev.ID_VISITA_MULTIPLE,
        TITULO_EVENTO: ev.TITULO_EVENTO,
        OBSERVACIONES_RESIDENTE: ev.OBSERVACIONES_RESIDENTE,
        FECHA_EVENTO: ev.FECHA_EVENTO,
        FECHA_VENCIMIENTO: ev.FECHA_VENCIMIENTO,
        ESTADO: ev.ESTADO,
        TOKEN_QR: ev.TOKEN_QR,
        qrCode: qrUrl,
        CONDOMINIO: ev.CONDOMINIO,
        RESIDENTE: persona.NOMBRE_PERSONA,
        totalInvitados: visitantesMapeados.length,
        totalIngresados: visitantesMapeados.filter((v) => v.ESTADO_INGRESO === "Ingresado").length,
        visitantes: visitantesMapeados,
      });
    }

    res.status(200).json(resultado);
  } catch (error) {
    console.error("Error al obtener visitas múltiples:", error);
    res.status(500).json({ error: "Error en el servidor al obtener visitas múltiples" });
  } finally {
    if (connection) connection.release();
  }
});

app.put("/actualizar_visita_multiple/:id", async (req, res) => {
  const { id } = req.params;
  const { TITULO_EVENTO, OBSERVACIONES_RESIDENTE, FECHA_EVENTO, VISITANTES } = req.body;

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    const [rows] = await connection.query(
      "SELECT * FROM TBL_REG_VISITAS_MULTIPLES WHERE ID_VISITA_MULTIPLE = ?",
      [id]
    );

    if (rows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Evento no encontrado" });
    }

    const ev = rows[0];
    if (ev.ESTADO !== "Activo") {
      await connection.rollback();
      return res.status(400).json({ error: "Solo se pueden editar eventos activos" });
    }

    let fechaEventoStr = ev.FECHA_EVENTO;
    let fechaVencimientoStr = ev.FECHA_VENCIMIENTO;
    if (FECHA_EVENTO) {
      let fechaEventoObj;
      if (moment(FECHA_EVENTO, "DD-MM-YYYY HH:mm", true).isValid()) {
        fechaEventoObj = moment.tz(FECHA_EVENTO, "DD-MM-YYYY HH:mm", "America/Tegucigalpa");
      } else {
        fechaEventoObj = moment.tz(FECHA_EVENTO, "America/Tegucigalpa");
      }
      fechaEventoStr = fechaEventoObj.format("YYYY-MM-DD HH:mm:ss");
      fechaVencimientoStr = fechaEventoObj.clone().endOf("day").format("YYYY-MM-DD 23:59:59");
    }

    const nuevoTitulo = TITULO_EVENTO !== undefined ? TITULO_EVENTO.trim() : ev.TITULO_EVENTO;
    const nuevasObs = OBSERVACIONES_RESIDENTE !== undefined ? (OBSERVACIONES_RESIDENTE ? OBSERVACIONES_RESIDENTE.trim() : null) : ev.OBSERVACIONES_RESIDENTE;

    await connection.query(
      `UPDATE TBL_REG_VISITAS_MULTIPLES
       SET TITULO_EVENTO = ?, OBSERVACIONES_RESIDENTE = ?, FECHA_EVENTO = ?, FECHA_VENCIMIENTO = ?
       WHERE ID_VISITA_MULTIPLE = ?`,
      [nuevoTitulo, nuevasObs, fechaEventoStr, fechaVencimientoStr, id]
    );

    if (Array.isArray(VISITANTES)) {
      const [ingresados] = await connection.query(
        "SELECT ID_DETALLE FROM TBL_DETALLE_VISITAS_MULTIPLES WHERE ID_VISITA_MULTIPLE = ? AND ESTADO_INGRESO = 'Ingresado'",
        [id]
      );
      const ingresadosIds = ingresados.map((r) => r.ID_DETALLE);

      if (ingresadosIds.length > 0) {
        await connection.query(
          "DELETE FROM TBL_DETALLE_VISITAS_MULTIPLES WHERE ID_VISITA_MULTIPLE = ? AND ESTADO_INGRESO != 'Ingresado'",
          [id]
        );
      } else {
        await connection.query(
          "DELETE FROM TBL_DETALLE_VISITAS_MULTIPLES WHERE ID_VISITA_MULTIPLE = ?",
          [id]
        );
      }

      for (const v of VISITANTES) {
        if (v.ID_DETALLE && ingresadosIds.includes(v.ID_DETALLE)) {
          continue;
        }
        const nombre = (v.nombre || v.NOMBRE_VISITANTE || "").toString().trim();
        const doc = v.documento || v.DOCUMENTO ? (v.documento || v.DOCUMENTO).toString().trim() : null;
        if (nombre.length > 0) {
          await connection.query(
            `INSERT INTO TBL_DETALLE_VISITAS_MULTIPLES
             (ID_VISITA_MULTIPLE, NOMBRE_VISITANTE, DOCUMENTO, ESTADO_INGRESO)
             VALUES (?, ?, ?, 'Pendiente')`,
            [id, nombre, doc]
          );
        }
      }
    }

    await connection.commit();

    const qrUrl = await new Promise((resolve) => {
      QRCode.toDataURL(ev.TOKEN_QR, (err, url) => {
        if (err) return resolve(null);
        resolve(url);
      });
    });

    res.status(200).json({
      message: "Visita múltiple actualizada exitosamente",
      qrCode: qrUrl,
      qrToken: ev.TOKEN_QR,
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al actualizar visita múltiple:", error);
    res.status(500).json({ error: "Error en el servidor al actualizar visita múltiple" });
  } finally {
    if (connection) connection.release();
  }
});

app.all("/cancelar_visita_multiple/:id", async (req, res) => {
  if (req.method !== "DELETE" && req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }
  const { id } = req.params;
  const motivo = (req.body && req.body.motivo) || req.query.motivo || "Cancelado por el residente";
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.query(
      "UPDATE TBL_REG_VISITAS_MULTIPLES SET ESTADO = 'Cancelado', MOTIVO_CANCELACION = ? WHERE ID_VISITA_MULTIPLE = ?",
      [motivo, id]
    );
    res.status(200).json({ message: "Visita múltiple cancelada exitosamente" });
  } catch (error) {
    console.error("Error al cancelar visita múltiple:", error);
    res.status(500).json({ error: "Error en el servidor al cancelar visita múltiple" });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/registrar_ingreso_multiple", async (req, res) => {
  const { ID_VISITA_MULTIPLE, ID_DETALLES, OBSERVACIONES_GUARDIA, USUARIO_GUARDIA } = req.body;
  if (!ID_VISITA_MULTIPLE || !Array.isArray(ID_DETALLES) || ID_DETALLES.length === 0) {
    return res.status(400).json({ error: "Debe seleccionar al menos un visitante" });
  }

  let connection;
  try {
    connection = await mysqlPool.getConnection();
    await connection.beginTransaction();

    const [eventoRows] = await connection.query(
      `SELECT e.*, per.NOMBRE_PERSONA, per.ID_CONDOMINIO, c.DESCRIPCION AS CONDOMINIO, u.EMAIL AS EMAIL_RESIDENTE, u.ID_USUARIO
       FROM TBL_REG_VISITAS_MULTIPLES e
       JOIN TBL_PERSONAS per ON e.ID_PERSONA = per.ID_PERSONA
       LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
       LEFT JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = per.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE e.ID_VISITA_MULTIPLE = ?`,
      [ID_VISITA_MULTIPLE]
    );

    if (eventoRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Visita múltiple no encontrada" });
    }

    const evento = eventoRows[0];
    const fechaIngreso = moment().tz("America/Tegucigalpa").format("YYYY-MM-DD HH:mm:ss");
    const obsGuardia = OBSERVACIONES_GUARDIA || "";
    const usuGuardia = USUARIO_GUARDIA || "Guardia de Caseta";

    const [visitantesActualizados] = await connection.query(
      `SELECT NOMBRE_VISITANTE, DOCUMENTO FROM TBL_DETALLE_VISITAS_MULTIPLES
       WHERE ID_DETALLE IN (?) AND ID_VISITA_MULTIPLE = ?`,
      [ID_DETALLES, ID_VISITA_MULTIPLE]
    );

    await connection.query(
      `UPDATE TBL_DETALLE_VISITAS_MULTIPLES
       SET ESTADO_INGRESO = 'Ingresado',
           FECHA_INGRESO = ?,
           OBSERVACIONES_GUARDIA = ?,
           USUARIO_GUARDIA = ?
       WHERE ID_DETALLE IN (?) AND ID_VISITA_MULTIPLE = ?`,
      [fechaIngreso, obsGuardia, usuGuardia, ID_DETALLES, ID_VISITA_MULTIPLE]
    );

    await connection.commit();

    const emailDestino = evento.EMAIL_RESIDENTE;
    if (emailDestino) {
      try {
        const listaNombresHtml = visitantesActualizados
          .map((v) => `<li><strong>${v.NOMBRE_VISITANTE}</strong>${v.DOCUMENTO ? ` (Doc: ${v.DOCUMENTO})` : ""}</li>`)
          .join("");

        const contenidoHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
            <div style="background-color: #14A13B; color: white; padding: 20px; text-align: center;">
              <h2 style="margin: 0;">Villa Las Acacias</h2>
              <p style="margin: 5px 0 0 0; font-size: 14px;">Control de Seguridad y Acceso - Visitas Múltiples</p>
            </div>
            <div style="padding: 24px; background-color: #ffffff;">
              <p style="font-size: 16px; color: #333333; margin-top: 0;">Estimado(a) <strong>${evento.NOMBRE_PERSONA}</strong>,</p>
              <p style="font-size: 14px; color: #555555; line-height: 1.5;">
                Le informamos que han ingresado visitantes autorizados de su reunión <strong>"${evento.TITULO_EVENTO}"</strong>:
              </p>
              <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px; margin: 16px 0;">
                <p style="margin: 0 0 8px 0; font-weight: bold; color: #1e293b;">Visitantes ingresados en caseta:</p>
                <ul style="margin: 0; padding-left: 20px; color: #334155;">
                  ${listaNombresHtml}
                </ul>
              </div>
              <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px;">
                <tr>
                  <td style="padding: 8px 0; color: #777777; width: 140px;">Casa / Condominio:</td>
                  <td style="padding: 8px 0; color: #333333; font-weight: bold;">${evento.CONDOMINIO || "N/A"}</td>
                </tr>
                <tr>
                  <td style="padding: 8px 0; color: #777777;">Fecha y Hora:</td>
                  <td style="padding: 8px 0; color: #333333; font-weight: bold;">${moment(fechaIngreso).tz("America/Tegucigalpa").format("DD/MM/YYYY hh:mm A")}</td>
                </tr>
                ${obsGuardia ? `
                <tr>
                  <td style="padding: 8px 0; color: #777777;">Observaciones Guardia:</td>
                  <td style="padding: 8px 0; color: #333333;">${obsGuardia}</td>
                </tr>
                ` : ""}
                <tr>
                  <td style="padding: 8px 0; color: #777777;">Registrado por:</td>
                  <td style="padding: 8px 0; color: #333333;">${usuGuardia}</td>
                </tr>
              </table>
            </div>
            <div style="background-color: #f9f9f9; padding: 12px; text-align: center; font-size: 12px; color: #888888; border-top: 1px solid #eeeeee;">
              Este es un mensaje automático del sistema de control de acceso de Villa Las Acacias.
            </div>
          </div>
        `;

        transporter.sendMail({
          from: "villalasacacias@villalasacacias.com",
          to: emailDestino,
          subject: `Villa Las Acacias - Notificación: Ingreso de Visita Múltiple (${evento.TITULO_EVENTO})`,
          html: contenidoHtml,
        }, (mailErr) => {
          if (mailErr) console.error("Error al enviar correo de visita múltiple:", mailErr);
        });
      } catch (mailErr) {
        console.error("Error al preparar correo de visita múltiple:", mailErr);
      }
    }

    if (evento.ID_USUARIO) {
      pushService.notificarUsuario(mysqlPool, evento.ID_USUARIO, {
        titulo: "Ingreso de visita múltiple registrado",
        mensaje: `Se registró el ingreso de ${ID_DETALLES.length} persona(s) a tu evento: ${evento.TITULO_EVENTO || ''}.`,
        tipo: "VISITA_MULTIPLE",
        data: {
          ruta: "/visitas_multiples",
          idVisitaMultiple: ID_VISITA_MULTIPLE
        }
      }).catch(err => console.error("Error push multiple usuario:", err));
    }

    if (evento.ID_CONDOMINIO) {
      pushService.notificarAdminCondominio(mysqlPool, evento.ID_CONDOMINIO, {
        titulo: "Ingreso de visitas a tu vivienda",
        mensaje: `Se registró el ingreso de ${ID_DETALLES.length} persona(s) para el evento: ${evento.TITULO_EVENTO || ''}.`,
        tipo: "VISITA_MULTIPLE",
        data: {
          ruta: "/visitas_multiples",
          idVisitaMultiple: ID_VISITA_MULTIPLE
        }
      }).catch(err => console.error("Error push multiple condominio:", err));
    }

    res.status(200).json({
      message: "Ingreso registrado exitosamente",
      cantidadIngresados: ID_DETALLES.length,
      fechaIngreso: fechaIngreso,
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al registrar ingreso de visita múltiple:", error);
    res.status(500).json({ error: "Error en el servidor al registrar ingreso" });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/reporte_visitas_multiples", async (req, res) => {
  const { condominio, fechaInicio, fechaFin, estado } = req.query;
  let connection;
  try {
    connection = await mysqlPool.getConnection();
    let querySql = `
      SELECT e.ID_VISITA_MULTIPLE, e.TITULO_EVENTO, e.OBSERVACIONES_RESIDENTE, e.FECHA_EVENTO,
             e.FECHA_VENCIMIENTO, e.ESTADO AS ESTADO_EVENTO,
             d.ID_DETALLE, d.NOMBRE_VISITANTE, d.DOCUMENTO, d.ESTADO_INGRESO, d.FECHA_INGRESO,
             d.OBSERVACIONES_GUARDIA, d.USUARIO_GUARDIA,
             per.NOMBRE_PERSONA AS RESIDENTE,
             c.ID_CONDOMINIO, c.DESCRIPCION AS CONDOMINIO
      FROM TBL_REG_VISITAS_MULTIPLES e
      JOIN TBL_PERSONAS per ON e.ID_PERSONA = per.ID_PERSONA
      LEFT JOIN TBL_CONDOMINIOS c ON per.ID_CONDOMINIO = c.ID_CONDOMINIO
      LEFT JOIN TBL_DETALLE_VISITAS_MULTIPLES d ON e.ID_VISITA_MULTIPLE = d.ID_VISITA_MULTIPLE
      WHERE 1=1
    `;
    const params = [];

    if (condominio) {
      querySql += " AND c.ID_CONDOMINIO = ?";
      params.push(condominio);
    }

    if (estado) {
      querySql += " AND d.ESTADO_INGRESO = ?";
      params.push(estado);
    }

    if (fechaInicio) {
      querySql += " AND DATE(e.FECHA_EVENTO) >= ?";
      params.push(fechaInicio);
    }

    if (fechaFin) {
      querySql += " AND DATE(e.FECHA_EVENTO) <= ?";
      params.push(fechaFin);
    }

    querySql += " ORDER BY c.DESCRIPCION ASC, e.FECHA_EVENTO DESC, d.ID_DETALLE ASC";

    const [rows] = await connection.query(querySql, params);
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener reporte de visitas múltiples:", error);
    res.status(500).json({ error: "Error en el servidor al generar reporte de visitas múltiples" });
  } finally {
    if (connection) connection.release();
  }
});


//*************** SOLICITUDES ADMINISTRATIVAS DE RESIDENTES ***************
{
  const ZONA = "America/Tegucigalpa";
  const CORREO_REMITENTE = "villalasacacias@villalasacacias.com";

  const ESTADO = {
    RECIBIDA: 1,
    PENDIENTE_REVISION: 1,
    EN_REVISION: 2,
    PENDIENTE_INFORMACION: 3,
  };
  const CANAL_APP = 1;
  const MAXIMO_ADJUNTOS = 3;
  const TAMANO_MAXIMO_BYTES = 2 * 1024 * 1024;
  const TIPOS_MIME_PERMITIDOS = ["image/jpeg", "image/png", "application/pdf"];

  function ahora() {
    return moment().tz(ZONA);
  }

  function calcularFechaLimite(desde, diasHabiles, feriados) {
    const fecha = moment.tz(desde.format("YYYY-MM-DD"), "YYYY-MM-DD", ZONA);
    let contados = 0;
    while (contados < diasHabiles) {
      fecha.add(1, "day");
      const dia = fecha.isoWeekday();
      if (dia >= 6 || feriados.includes(fecha.format("YYYY-MM-DD"))) {
        continue;
      }
      contados++;
    }
    return fecha;
  }

  function numeroSeguimiento(idSolicitud, anio) {
    return `SOL-${anio}-${String(idSolicitud).padStart(5, "0")}`;
  }

  function texto(valor) {
    return typeof valor === "string" ? valor.trim() : "";
  }

  function escaparHtml(valor) {
    return String(valor ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  class ErrorSolicitud extends Error {
    constructor(status, mensaje) {
      super(mensaje);
      this.status = status;
    }
  }

  // Detecta el tipo real del archivo por su contenido (firma / "magic bytes"),
  // sin confiar en el MIME que envía el cliente.
  function detectarMime(buffer) {
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "image/jpeg";
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
    if (buffer.length >= 5 && buffer.subarray(0, 5).toString("latin1") === "%PDF-") return "application/pdf";
    return null;
  }

  function validarAdjuntos(adjuntos, yaGuardados) {
    if (adjuntos === undefined || adjuntos === null) return [];
    if (!Array.isArray(adjuntos)) throw new ErrorSolicitud(400, "Formato de adjuntos inválido");
    if (adjuntos.length + yaGuardados > MAXIMO_ADJUNTOS) {
      throw new ErrorSolicitud(400, `Solo se permiten ${MAXIMO_ADJUNTOS} adjuntos por solicitud`);
    }
    return adjuntos.map((adjunto) => {
      const base64 = texto(adjunto && adjunto.base64);
      if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
        throw new ErrorSolicitud(400, "Adjunto dañado");
      }
      const contenido = Buffer.from(base64, "base64");
      const mime = detectarMime(contenido);
      if (!mime || !TIPOS_MIME_PERMITIDOS.includes(mime)) {
        throw new ErrorSolicitud(400, "Solo se permiten imágenes JPG/PNG o PDF");
      }
      const bytes = contenido.length;
      if (bytes === 0 || bytes > TAMANO_MAXIMO_BYTES) {
        throw new ErrorSolicitud(400, "Cada adjunto debe pesar menos de 2 MB");
      }
      const nombre = (texto(adjunto.nombre) || "adjunto").replace(/[\\/:*?"<>|]/g, "_").slice(0, 255);
      return { nombre, mime, base64, bytes };
    });
  }

  function usuarioSolicitado(req) {
    const valor = req.method === "GET" ? req.query.usuarioId : req.body && req.body.usuarioId;
    const usuarioId = parseInt(valor, 10);
    if (!Number.isInteger(usuarioId) || usuarioId <= 0) {
      throw new ErrorSolicitud(400, "Se requiere usuarioId");
    }
    const encabezado = req.headers["authorization"];
    if (encabezado && jwt && SECRET_KEY) {
      const token = String(encabezado).replace(/^Bearer\s+/i, "");
      try {
        const decodificado = jwt.verify(token, SECRET_KEY);
        if (decodificado && decodificado.id && Number(decodificado.id) !== usuarioId) {
          throw new ErrorSolicitud(403, "El usuario no coincide con la sesión");
        }
      } catch (error) {
        if (error instanceof ErrorSolicitud) throw error;
      }
    }
    return usuarioId;
  }

  async function personaDelUsuario(connection, usuarioId) {
    const [usuarios] = await connection.query(
      "SELECT ID_USUARIO, NOMBRE_USUARIO, EMAIL FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?",
      [usuarioId]
    );
    if (usuarios.length === 0) throw new ErrorSolicitud(404, "Usuario no encontrado");
    const [personas] = await connection.query(
      `SELECT p.ID_PERSONA, p.NOMBRE_PERSONA, p.ID_CONDOMINIO, p.ID_PADRE, c.DESCRIPCION AS CASA
       FROM TBL_PERSONAS p
       LEFT JOIN TBL_CONDOMINIOS c ON p.ID_CONDOMINIO = c.ID_CONDOMINIO
       WHERE p.NOMBRE_PERSONA = ?
       ORDER BY p.ID_PERSONA DESC
       LIMIT 1`,
      [usuarios[0].NOMBRE_USUARIO]
    );
    if (personas.length === 0) throw new ErrorSolicitud(404, "Persona asociada no encontrada");
    if (!personas[0].ID_CONDOMINIO) throw new ErrorSolicitud(400, "Su usuario no tiene una casa asignada");
    return { ...personas[0], EMAIL: usuarios[0].EMAIL, ID_USUARIO: usuarios[0].ID_USUARIO };
  }

  function filtroAcceso(persona) {
    if (Number(persona.ID_PADRE) === 1) {
      return { sql: "s.ID_CONDOMINIO = ?", parametros: [persona.ID_CONDOMINIO] };
    }
    return { sql: "s.ID_PERSONA = ?", parametros: [persona.ID_PERSONA] };
  }

  const SELECT_SOLICITUD = `
    SELECT s.ID_SOLICITUD, s.NUMERO_SEGUIMIENTO, s.ID_PERSONA, s.ID_CONDOMINIO, s.ID_TIPO_SOLICITUD, s.ID_USUARIO_ASIGNADO,
           s.ID_ESTADO_SOLICITUD, s.ASUNTO, s.DESCRIPCION, s.JUSTIFICACION, s.PRIORIDAD,
           DATE_FORMAT(s.FECHA_PRESENTACION, '%Y-%m-%d %H:%i:%s') AS FECHA_PRESENTACION,
           DATE_FORMAT(s.FECHA_LIMITE, '%Y-%m-%d') AS FECHA_LIMITE,
           DATE_FORMAT(s.FECHA_RESPUESTA, '%Y-%m-%d %H:%i:%s') AS FECHA_RESPUESTA,
           s.RESPUESTA_OFICIAL, p.NOMBRE_PERSONA AS RESIDENTE, c.DESCRIPCION AS CASA,
           t.DESCRIPCION AS TIPO, e.DESCRIPCION AS ESTADO, e.COLOR AS COLOR_ESTADO, e.ES_FINAL,
           CASE WHEN e.ES_FINAL = 0 AND s.FECHA_RESPUESTA IS NULL AND s.FECHA_LIMITE < ? THEN 1 ELSE 0 END AS VENCIDA
    FROM TBL_SOLICITUDES s
    JOIN TBL_PERSONAS p ON s.ID_PERSONA = p.ID_PERSONA
    JOIN TBL_CONDOMINIOS c ON s.ID_CONDOMINIO = c.ID_CONDOMINIO
    JOIN TBL_TIPO_SOLICITUD t ON s.ID_TIPO_SOLICITUD = t.ID_TIPO_SOLICITUD
    JOIN TBL_ESTADO_SOLICITUD e ON s.ID_ESTADO_SOLICITUD = e.ID_ESTADO_SOLICITUD`;

  async function solicitudConAcceso(connection, persona, condicion, valor) {
    const acceso = filtroAcceso(persona);
    const [filas] = await connection.query(
      `${SELECT_SOLICITUD} WHERE ${condicion} AND ${acceso.sql}`,
      [ahora().format("YYYY-MM-DD"), valor, ...acceso.parametros]
    );
    if (filas.length === 0) throw new ErrorSolicitud(404, "No se encontró la solicitud o no pertenece a su casa");
    return filas[0];
  }

  async function guardarAdjuntos(connection, idSolicitud, adjuntos, usuarioId) {
    for (const adjunto of adjuntos) {
      await connection.query(
        `INSERT INTO TBL_SOLICITUD_ADJUNTOS
         (ID_SOLICITUD, NOMBRE_ORIGINAL, TIPO_MIME, TAMANO_BYTES, CONTENIDO_BASE64, SUBIDO_POR, FECHA_HORA)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [idSolicitud, adjunto.nombre, adjunto.mime, adjunto.bytes, adjunto.base64, usuarioId, ahora().format("YYYY-MM-DD HH:mm:ss")]
      );
    }
  }

  function enviarCorreo(opciones) {
    if (!transporter) return;
    transporter.sendMail({ from: CORREO_REMITENTE, ...opciones }, (error) => {
      if (error) console.error("Solicitudes: error al enviar correo:", error.message);
    });
  }

  function responderError(res, error, contexto) {
    if (error instanceof ErrorSolicitud) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error(`Solicitudes: error en ${contexto}:`, error);
    return res.status(500).json({ error: "Error en el servidor" });
  }

  app.get("/tipos_solicitud_admin", async (req, res) => {
    try {
      const [tipos] = await mysqlPool.query(
        `SELECT ID_TIPO_SOLICITUD, DESCRIPCION, DETALLE, DIAS_PLAZO, PRIORIDAD_DEFECTO
         FROM TBL_TIPO_SOLICITUD WHERE ACTIVO = 1 ORDER BY ID_TIPO_SOLICITUD`
      );
      res.status(200).json(tipos);
    } catch (error) {
      responderError(res, error, "tipos_solicitud_admin");
    }
  });

  app.post("/registrar_solicitud_admin", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      const idTipo = parseInt(req.body.ID_TIPO_SOLICITUD, 10);
      const asunto = texto(req.body.ASUNTO).toLocaleUpperCase("es");
      const descripcion = texto(req.body.DESCRIPCION).toLocaleUpperCase("es");
      const justificacion = texto(req.body.JUSTIFICACION || req.body.DESCRIPCION).toLocaleUpperCase("es");

      if (!Number.isInteger(idTipo)) throw new ErrorSolicitud(400, "Seleccione el tipo de solicitud");
      if (asunto.length < 5 || asunto.length > 150) throw new ErrorSolicitud(400, "El asunto debe tener entre 5 y 150 caracteres");
      if (descripcion.length < 10 || descripcion.length > 5000) throw new ErrorSolicitud(400, "La descripción debe tener entre 10 y 5000 caracteres");
      const adjuntos = validarAdjuntos(req.body.ADJUNTOS, 0);

      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);

      const [tipos] = await connection.query(
        "SELECT ID_TIPO_SOLICITUD, DESCRIPCION, DIAS_PLAZO, PRIORIDAD_DEFECTO FROM TBL_TIPO_SOLICITUD WHERE ID_TIPO_SOLICITUD = ? AND ACTIVO = 1",
        [idTipo]
      );
      if (tipos.length === 0) throw new ErrorSolicitud(400, "El tipo de solicitud no está disponible");
      const tipo = tipos[0];

      const [parametros] = await connection.query(
        "SELECT VALOR FROM TBL_MS_PARAMETROS WHERE PARAMETRO = 'SOLICITUD_FERIADOS' LIMIT 1"
      );
      const feriados = String((parametros[0] && parametros[0].VALOR) || "")
        .split(",")
        .map((f) => f.trim())
        .filter((f) => /^\d{4}-\d{2}-\d{2}$/.test(f));

      const presentacion = ahora();
      const limite = calcularFechaLimite(presentacion, Number(tipo.DIAS_PLAZO), feriados);

      await connection.beginTransaction();
      const [insercion] = await connection.query(
        `INSERT INTO TBL_SOLICITUDES
         (ID_PERSONA, ID_CONDOMINIO, ID_TIPO_SOLICITUD, ID_ESTADO_SOLICITUD, ID_CANAL_SOLICITUD, ASUNTO, DESCRIPCION,
          JUSTIFICACION, PRIORIDAD, FECHA_PRESENTACION, FECHA_LIMITE, CREADO_POR, FECHA_CREACION)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          persona.ID_PERSONA,
          persona.ID_CONDOMINIO,
          tipo.ID_TIPO_SOLICITUD,
          ESTADO.RECIBIDA,
          CANAL_APP,
          asunto,
          descripcion,
          justificacion,
          tipo.PRIORIDAD_DEFECTO,
          presentacion.format("YYYY-MM-DD HH:mm:ss"),
          limite.format("YYYY-MM-DD"),
          usuarioId,
          presentacion.format("YYYY-MM-DD HH:mm:ss"),
        ]
      );
      const idSolicitud = insercion.insertId;
      const numero = numeroSeguimiento(idSolicitud, presentacion.year());
      await connection.query("UPDATE TBL_SOLICITUDES SET NUMERO_SEGUIMIENTO = ? WHERE ID_SOLICITUD = ?", [numero, idSolicitud]);
      await connection.query(
        `INSERT INTO TBL_SOLICITUD_SEGUIMIENTO
         (ID_SOLICITUD, ID_ESTADO_ANTERIOR, ID_ESTADO_NUEVO, OBSERVACION, VISIBLE_RESIDENTE, ES_RESIDENTE, ID_USUARIO, FECHA_HORA)
         VALUES (?, NULL, ?, ?, 1, 1, ?, ?)`,
        [idSolicitud, ESTADO.RECIBIDA, `Solicitud enviada desde la aplicación con el número ${numero}.`, usuarioId, presentacion.format("YYYY-MM-DD HH:mm:ss")]
      );
      await guardarAdjuntos(connection, idSolicitud, adjuntos, usuarioId);
      await connection.commit();

      const limiteTexto = limite.format("DD/MM/YYYY");
      if (persona.EMAIL) {
        enviarCorreo({
          to: persona.EMAIL,
          subject: `Solicitud ${numero} registrada (Pendiente de revisión)`,
          html: `
            <p>Estimado/a ${escaparHtml(persona.NOMBRE_PERSONA)},</p>
            <p>La Administración de Villa Las Acacias registró su solicitud (Pendiente de revisión).</p>
            <p><strong>Número de seguimiento:</strong> ${numero}<br>
               <strong>Tipo:</strong> ${escaparHtml(tipo.DESCRIPCION)}<br>
               <strong>Asunto:</strong> ${escaparHtml(asunto)}<br>
               <strong>Fecha límite de respuesta:</strong> ${limiteTexto}</p>
            <p>Puede dar seguimiento en la aplicación, opción <em>Mis Solicitudes</em>.</p>
            <p>Atentamente,</p>
            <p>El equipo de administración de Villas Las Acacias</p>`,
        });
      }
      const [administradores] = await mysqlPool.query("SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4) AND EMAIL IS NOT NULL");
      if (administradores.length > 0) {
        enviarCorreo({
          to: administradores.map((a) => a.EMAIL),
          subject: `Nueva solicitud ${numero} - ${tipo.DESCRIPCION}`,
          html: `
            <p>Estimados Administradores,</p>
            <p>Se recibió una nueva solicitud desde la aplicación:</p>
            <p><strong>Número:</strong> ${numero}<br>
               <strong>Residente:</strong> ${escaparHtml(persona.NOMBRE_PERSONA)}<br>
               <strong>Casa:</strong> ${escaparHtml(persona.CASA)}<br>
               <strong>Tipo:</strong> ${escaparHtml(tipo.DESCRIPCION)}<br>
               <strong>Asunto:</strong> ${escaparHtml(asunto)}<br>
               <strong>Responder a más tardar:</strong> ${limiteTexto}</p>
            <p>Puede gestionarla en el panel web, menú Solicitudes de Residentes.</p>`,
        });
      }

      pushService.notificarUsuario(mysqlPool, usuarioId, {
        titulo: `Solicitud ${numero} registrada`,
        mensaje: `Tu solicitud sobre "${asunto}" ha sido registrada y está pendiente de revisión.`,
        tipo: "SOLICITUD",
        data: {
          ruta: "/Mis_solicitudes",
          idSolicitud: idSolicitud,
          numero: numero,
        },
      }).catch(() => {});

      pushService.notificarRoles(mysqlPool, [1, 4], {
        titulo: `Nueva Solicitud: ${tipo.DESCRIPCION}`,
        mensaje: `${persona.NOMBRE_PERSONA} (${persona.CASA}) envió la solicitud ${numero}: ${asunto}`,
        tipo: "SOLICITUD",
        data: {
          ruta: "/Mis_solicitudes",
          idSolicitud: idSolicitud,
          numero: numero,
        },
      }).catch(() => {});

      res.status(201).json({
        message: "Solicitud registrada exitosamente",
        idSolicitud,
        numero,
        fechaLimite: limite.format("YYYY-MM-DD"),
      });
    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch (_) {}
      }
      responderError(res, error, "registrar_solicitud_admin");
    } finally {
      if (connection) connection.release();
    }
  });

  app.get("/mis_solicitudes_admin", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);
      const acceso = filtroAcceso(persona);
      const [filas] = await connection.query(
        `${SELECT_SOLICITUD} WHERE ${acceso.sql}
         ORDER BY e.ES_FINAL ASC, s.FECHA_PRESENTACION DESC`,
        [ahora().format("YYYY-MM-DD"), ...acceso.parametros]
      );
      res.status(200).json(filas.map(({ DESCRIPCION, JUSTIFICACION, RESPUESTA_OFICIAL, ...resto }) => resto));
    } catch (error) {
      responderError(res, error, "mis_solicitudes_admin");
    } finally {
      if (connection) connection.release();
    }
  });

  app.get("/detalle_solicitud_admin", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);

      let solicitud;
      if (req.query.id) {
        solicitud = await solicitudConAcceso(connection, persona, "s.ID_SOLICITUD = ?", parseInt(req.query.id, 10));
      } else if (req.query.numero) {
        solicitud = await solicitudConAcceso(connection, persona, "s.NUMERO_SEGUIMIENTO = ?", texto(req.query.numero).toUpperCase());
      } else {
        throw new ErrorSolicitud(400, "Indique el número de seguimiento");
      }

      const [seguimiento] = await connection.query(
        `SELECT g.ID_SEGUIMIENTO, g.OBSERVACION, g.ES_RESIDENTE,
                DATE_FORMAT(g.FECHA_HORA, '%Y-%m-%d %H:%i:%s') AS FECHA_HORA,
                en.DESCRIPCION AS ESTADO_NUEVO, en.COLOR AS COLOR_ESTADO
         FROM TBL_SOLICITUD_SEGUIMIENTO g
         JOIN TBL_ESTADO_SOLICITUD en ON g.ID_ESTADO_NUEVO = en.ID_ESTADO_SOLICITUD
         WHERE g.ID_SOLICITUD = ? AND g.VISIBLE_RESIDENTE = 1
         ORDER BY g.FECHA_HORA, g.ID_SEGUIMIENTO`,
        [solicitud.ID_SOLICITUD]
      );
      const [adjuntos] = await connection.query(
        `SELECT a.ID_ADJUNTO, a.NOMBRE_ORIGINAL, a.TIPO_MIME, a.TAMANO_BYTES,
                CASE WHEN u.ID_ROL IN (1, 4, 5) THEN 1 ELSE 0 END AS DE_ADMINISTRACION
         FROM TBL_SOLICITUD_ADJUNTOS a
         LEFT JOIN TBL_MS_USUARIO u ON u.ID_USUARIO = a.SUBIDO_POR
         WHERE a.ID_SOLICITUD = ? ORDER BY a.ID_ADJUNTO`,
        [solicitud.ID_SOLICITUD]
      );
      res.status(200).json({ ...solicitud, SEGUIMIENTO: seguimiento, ADJUNTOS: adjuntos });
    } catch (error) {
      responderError(res, error, "detalle_solicitud_admin");
    } finally {
      if (connection) connection.release();
    }
  });

  app.post("/responder_solicitud_admin", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      const idSolicitud = parseInt(req.body.idSolicitud, 10);
      const mensaje = texto(req.body.MENSAJE).toLocaleUpperCase("es");
      if (!Number.isInteger(idSolicitud)) throw new ErrorSolicitud(400, "Solicitud no válida");
      if (mensaje.length < 5 || mensaje.length > 2000) throw new ErrorSolicitud(400, "El mensaje debe tener entre 5 y 2000 caracteres");

      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);
      const solicitud = await solicitudConAcceso(connection, persona, "s.ID_SOLICITUD = ?", idSolicitud);
      if (Number(solicitud.ES_FINAL) === 1) throw new ErrorSolicitud(400, "La solicitud ya está cerrada");

      const [conteo] = await connection.query("SELECT COUNT(*) AS TOTAL FROM TBL_SOLICITUD_ADJUNTOS WHERE ID_SOLICITUD = ?", [idSolicitud]);
      const adjuntos = validarAdjuntos(req.body.ADJUNTOS, Number(conteo[0].TOTAL));

      const estadoActual = Number(solicitud.ID_ESTADO_SOLICITUD);
      const estadoNuevo = estadoActual === ESTADO.PENDIENTE_INFORMACION ? ESTADO.EN_REVISION : estadoActual;
      const fecha = ahora().format("YYYY-MM-DD HH:mm:ss");

      await connection.beginTransaction();
      const [bloqueo] = await connection.query("SELECT ID_ESTADO_SOLICITUD FROM TBL_SOLICITUDES WHERE ID_SOLICITUD = ? FOR UPDATE", [idSolicitud]);
      if (Number(bloqueo[0].ID_ESTADO_SOLICITUD) !== estadoActual) {
        throw new ErrorSolicitud(409, "La solicitud cambió de estado, actualice la pantalla");
      }
      if (estadoNuevo !== estadoActual) {
        await connection.query("UPDATE TBL_SOLICITUDES SET ID_ESTADO_SOLICITUD = ? WHERE ID_SOLICITUD = ?", [estadoNuevo, idSolicitud]);
      }
      await connection.query(
        `INSERT INTO TBL_SOLICITUD_SEGUIMIENTO
         (ID_SOLICITUD, ID_ESTADO_ANTERIOR, ID_ESTADO_NUEVO, OBSERVACION, VISIBLE_RESIDENTE, ES_RESIDENTE, ID_USUARIO, FECHA_HORA)
         VALUES (?, ?, ?, ?, 1, 1, ?, ?)`,
        [idSolicitud, estadoActual, estadoNuevo, mensaje, usuarioId, fecha]
      );
      await guardarAdjuntos(connection, idSolicitud, adjuntos, usuarioId);
      await connection.commit();

      const idAdminAsignado = solicitud.ID_USUARIO_ASIGNADO ? Number(solicitud.ID_USUARIO_ASIGNADO) : null;
      if (idAdminAsignado) {
        const [adminRows] = await mysqlPool.query("SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_USUARIO = ?", [idAdminAsignado]);
        if (adminRows.length > 0 && adminRows[0].EMAIL) {
          enviarCorreo({
            to: adminRows[0].EMAIL,
            subject: `Respuesta del residente en ${solicitud.NUMERO_SEGUIMIENTO}`,
            html: `
              <p>El residente ${escaparHtml(persona.NOMBRE_PERSONA)} (casa ${escaparHtml(solicitud.CASA)}) agregó información a la solicitud <strong>${solicitud.NUMERO_SEGUIMIENTO}</strong> asignada a usted:</p>
              <p style="background:#f4f6f9;padding:10px;border-left:4px solid #14A13B;">${escaparHtml(mensaje)}</p>`,
          });
        }
        pushService.notificarUsuario(mysqlPool, idAdminAsignado, {
          titulo: `Respuesta en Solicitud ${solicitud.NUMERO_SEGUIMIENTO}`,
          mensaje: `${persona.NOMBRE_PERSONA} (${solicitud.CASA}) respondió: ${mensaje.substring(0, 100)}`,
          tipo: "SOLICITUD",
          data: {
            ruta: "/Mis_solicitudes",
            idSolicitud: solicitud.ID_SOLICITUD,
            numero: solicitud.NUMERO_SEGUIMIENTO,
          },
        }).catch(() => {});
      } else {
        const [administradores] = await mysqlPool.query("SELECT EMAIL FROM TBL_MS_USUARIO WHERE ID_ROL IN (1, 4) AND EMAIL IS NOT NULL");
        if (administradores.length > 0) {
          enviarCorreo({
            to: administradores.map((a) => a.EMAIL),
            subject: `Respuesta del residente en ${solicitud.NUMERO_SEGUIMIENTO}`,
            html: `
              <p>El residente ${escaparHtml(persona.NOMBRE_PERSONA)} (casa ${escaparHtml(solicitud.CASA)}) agregó información a la solicitud <strong>${solicitud.NUMERO_SEGUIMIENTO}</strong>:</p>
              <p style="background:#f4f6f9;padding:10px;border-left:4px solid #14A13B;">${escaparHtml(mensaje)}</p>`,
          });
        }
        pushService.notificarRoles(mysqlPool, [1, 4], {
          titulo: `Respuesta en Solicitud ${solicitud.NUMERO_SEGUIMIENTO}`,
          mensaje: `${persona.NOMBRE_PERSONA} (${solicitud.CASA}) agregó nueva información.`,
          tipo: "SOLICITUD",
          data: {
            ruta: "/Mis_solicitudes",
            idSolicitud: solicitud.ID_SOLICITUD,
            numero: solicitud.NUMERO_SEGUIMIENTO,
          },
        }).catch(() => {});
      }

      res.status(200).json({
        message: estadoNuevo !== estadoActual
          ? "Información enviada. Su solicitud volvió a revisión."
          : "Comentario enviado a la Administración.",
      });
    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch (_) {}
      }
      responderError(res, error, "responder_solicitud_admin");
    } finally {
      if (connection) connection.release();
    }
  });

  app.post("/solicitudes_admin/cambiar_prioridad", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      const { idSolicitud, prioridad } = req.body;
      const prioridadNorm = String(prioridad || "").trim().toLowerCase();
      const prioridadesValidas = { baja: "Baja", media: "Media", alta: "Alta" };
      if (!prioridadesValidas[prioridadNorm]) {
        throw new ErrorSolicitud(400, "Prioridad no válida. Debe ser Baja, Media o Alta");
      }
      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);
      if (![1, 4, 5].includes(persona.ID_ROL)) {
        throw new ErrorSolicitud(403, "Solo el administrador o junta pueden cambiar la prioridad del ticket");
      }
      const [solicitudes] = await connection.query(
        "SELECT ID_SOLICITUD, NUMERO_SEGUIMIENTO, PRIORIDAD, ID_ESTADO_SOLICITUD FROM TBL_SOLICITUDES WHERE ID_SOLICITUD = ?",
        [idSolicitud]
      );
      if (solicitudes.length === 0) throw new ErrorSolicitud(404, "Solicitud no encontrada");
      const sol = solicitudes[0];
      const nuevaPrioridad = prioridadesValidas[prioridadNorm];
      if (sol.PRIORIDAD !== nuevaPrioridad) {
        await connection.query("UPDATE TBL_SOLICITUDES SET PRIORIDAD = ? WHERE ID_SOLICITUD = ?", [nuevaPrioridad, idSolicitud]);
        await connection.query(
          `INSERT INTO TBL_SOLICITUD_SEGUIMIENTO
           (ID_SOLICITUD, ID_ESTADO_ANTERIOR, ID_ESTADO_NUEVO, OBSERVACION, VISIBLE_RESIDENTE, ES_RESIDENTE, ID_USUARIO, FECHA_HORA)
           VALUES (?, ?, ?, ?, 1, 0, ?, ?)`,
          [idSolicitud, sol.ID_ESTADO_SOLICITUD, sol.ID_ESTADO_SOLICITUD, `Prioridad actualizada de ${sol.PRIORIDAD || "Media"} a ${nuevaPrioridad}`, usuarioId, ahora().toDate()]
        );
        const [usuariosCasa] = await connection.query(
          `SELECT u.ID_USUARIO 
           FROM TBL_SOLICITUDES s 
           JOIN TBL_PERSONAS p ON s.ID_PERSONA = p.ID_PERSONA 
           JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci 
           WHERE s.ID_SOLICITUD = ?`,
          [idSolicitud]
        );
        for (const u of usuariosCasa) {
          pushService.notificarUsuario(mysqlPool, u.ID_USUARIO, {
            titulo: `Solicitud ${sol.NUMERO_SEGUIMIENTO}`,
            mensaje: `La prioridad fue actualizada a ${nuevaPrioridad}`,
            tipo: "SOLICITUD",
            data: { ruta: "/Mis_solicitudes", idSolicitud: idSolicitud, numero: sol.NUMERO_SEGUIMIENTO }
          }).catch(() => {});
        }
      }
      res.status(200).json({ message: "Prioridad actualizada correctamente", prioridad: nuevaPrioridad });
    } catch (error) {
      responderError(res, error, "cambiar_prioridad_solicitud");
    } finally {
      if (connection) connection.release();
    }
  });

  app.get("/adjunto_solicitud_admin", async (req, res) => {
    let connection;
    try {
      const usuarioId = usuarioSolicitado(req);
      const idAdjunto = parseInt(req.query.id, 10);
      if (!Number.isInteger(idAdjunto)) throw new ErrorSolicitud(400, "Adjunto no válido");
      connection = await mysqlPool.getConnection();
      const persona = await personaDelUsuario(connection, usuarioId);
      const [adjuntos] = await connection.query(
        "SELECT ID_ADJUNTO, ID_SOLICITUD, NOMBRE_ORIGINAL, TIPO_MIME, CONTENIDO_BASE64 FROM TBL_SOLICITUD_ADJUNTOS WHERE ID_ADJUNTO = ?",
        [idAdjunto]
      );
      if (adjuntos.length === 0) throw new ErrorSolicitud(404, "Adjunto no encontrado");
      await solicitudConAcceso(connection, persona, "s.ID_SOLICITUD = ?", adjuntos[0].ID_SOLICITUD);
      res.status(200).json(adjuntos[0]);
    } catch (error) {
      responderError(res, error, "adjunto_solicitud_admin");
    } finally {
      if (connection) connection.release();
    }
  });
}


app.post("/enviar_notificacion_push", async (req, res) => {
  const { usuarioId, titulo, mensaje, tipo, data, soloPush } = req.body;
  if (!usuarioId || !titulo || !mensaje) {
    return res.status(400).json({ error: "usuarioId, titulo y mensaje son requeridos" });
  }
  try {
    await pushService.notificarUsuario(mysqlPool, usuarioId, {
      titulo,
      mensaje,
      tipo: tipo || "SOLICITUD",
      data: data || {},
      soloPush: !!soloPush,
    });
    res.status(200).json({ message: "Notificación push despachada exitosamente" });
  } catch (error) {
    console.error("Error al despachar push:", error);
    res.status(500).json({ error: "Error interno al despachar push" });
  }
});

app.post("/enviar_notificacion_push_global", async (req, res) => {
  const { titulo, mensaje, tipo, data } = req.body;
  if (!titulo || !mensaje) {
    return res.status(400).json({ error: "titulo y mensaje son requeridos" });
  }
  try {
    await pushService.notificarGlobal(mysqlPool, {
      titulo,
      mensaje,
      tipo: tipo || "ANUNCIO",
      data: data || {},
    });
    res.status(200).json({ message: "Notificación push global despachada exitosamente" });
  } catch (error) {
    console.error("Error al despachar push global:", error);
    res.status(500).json({ error: "Error interno al despachar push global" });
  }
});

app.post("/enviar_notificacion_push_roles", async (req, res) => {
  const { roles, titulo, mensaje, tipo, data } = req.body;
  if (!roles || !titulo || !mensaje) {
    return res.status(400).json({ error: "roles, titulo y mensaje son requeridos" });
  }
  try {
    const rolesArray = Array.isArray(roles) ? roles : [Number(roles)];
    await pushService.notificarRoles(mysqlPool, rolesArray, {
      titulo,
      mensaje,
      tipo: tipo || "GENERAL",
      data: data || {},
    });
    res.status(200).json({ message: "Notificación push a roles despachada exitosamente" });
  } catch (error) {
    console.error("Error al despachar push a roles:", error);
    res.status(500).json({ error: "Error interno al despachar push a roles" });
  }
});

app.post("/guardar_token_fcm", async (req, res) => {
  const { usuarioId, fcmToken, plataforma } = req.body;
  if (!usuarioId || !fcmToken) {
    return res.status(400).json({ error: "usuarioId y fcmToken son requeridos" });
  }
  try {
    await pushService.guardarTokenDispositivo(mysqlPool, usuarioId, fcmToken, plataforma || "Android");
    res.status(200).json({ message: "Token FCM registrado exitosamente" });
  } catch (error) {
    console.error("Error al guardar token FCM:", error);
    res.status(500).json({ error: "Error en el servidor al guardar token" });
  }
});

app.get("/mis_notificaciones/:usuarioId", async (req, res) => {
  const { usuarioId } = req.params;
  try {
    const [notificaciones] = await mysqlPool.query(
      `SELECT ID_NOTIFICACION, ID_USUARIO, TITULO, MENSAJE, TIPO, LEIDO, DATOS_EXTRA, FECHA_CREACION
       FROM TBL_NOTIFICACIONES
       WHERE ID_USUARIO = ?
       ORDER BY FECHA_CREACION DESC
       LIMIT 60`,
      [usuarioId]
    );
    res.status(200).json(notificaciones);
  } catch (error) {
    console.error("Error al obtener notificaciones:", error);
    res.status(500).json({ error: "Error al obtener notificaciones" });
  }
});

app.get("/conteo_notificaciones_no_leidas/:usuarioId", async (req, res) => {
  const { usuarioId } = req.params;
  try {
    const [rows] = await mysqlPool.query(
      `SELECT COUNT(*) AS noLeidas
       FROM TBL_NOTIFICACIONES
       WHERE ID_USUARIO = ? AND LEIDO = 0`,
      [usuarioId]
    );
    res.status(200).json({ noLeidas: rows[0].noLeidas || 0 });
  } catch (error) {
    console.error("Error al contar notificaciones no leídas:", error);
    res.status(500).json({ error: "Error al contar notificaciones" });
  }
});

app.post("/marcar_notificacion_leida/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await mysqlPool.query(
      "UPDATE TBL_NOTIFICACIONES SET LEIDO = 1 WHERE ID_NOTIFICACION = ?",
      [id]
    );
    res.status(200).json({ message: "Notificación marcada como leída" });
  } catch (error) {
    console.error("Error al marcar notificación leída:", error);
    res.status(500).json({ error: "Error al actualizar notificación" });
  }
});

app.post("/toggle_notificacion_leida/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await mysqlPool.query(
      "UPDATE TBL_NOTIFICACIONES SET LEIDO = CASE WHEN LEIDO = 1 THEN 0 ELSE 1 END WHERE ID_NOTIFICACION = ?",
      [id]
    );
    res.status(200).json({ message: "Estado de lectura actualizado" });
  } catch (error) {
    console.error("Error al alternar estado de notificación:", error);
    res.status(500).json({ error: "Error al actualizar notificación" });
  }
});

app.post("/marcar_todas_notificaciones_leidas", async (req, res) => {
  const { usuarioId } = req.body;
  if (!usuarioId) {
    return res.status(400).json({ error: "usuarioId es requerido" });
  }
  try {
    await mysqlPool.query(
      "UPDATE TBL_NOTIFICACIONES SET LEIDO = 1 WHERE ID_USUARIO = ? AND LEIDO = 0",
      [usuarioId]
    );
    res.status(200).json({ message: "Todas las notificaciones fueron marcadas como leídas" });
  } catch (error) {
    console.error("Error al marcar todas como leídas:", error);
    res.status(500).json({ error: "Error al actualizar notificaciones" });
  }
});

app.delete("/eliminar_notificacion/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await mysqlPool.query(
      "DELETE FROM TBL_NOTIFICACIONES WHERE ID_NOTIFICACION = ?",
      [id]
    );
    res.status(200).json({ message: "Notificación eliminada exitosamente" });
  } catch (error) {
    console.error("Error al eliminar notificación:", error);
    res.status(500).json({ error: "Error al eliminar notificación" });
  }
});

app.delete("/eliminar_todas_notificaciones/:usuarioId", async (req, res) => {
  const { usuarioId } = req.params;
  try {
    await mysqlPool.query(
      "DELETE FROM TBL_NOTIFICACIONES WHERE ID_USUARIO = ?",
      [usuarioId]
    );
    res.status(200).json({ message: "Historial de notificaciones eliminado" });
  } catch (error) {
    console.error("Error al eliminar todas las notificaciones:", error);
    res.status(500).json({ error: "Error al eliminar historial" });
  }
});

app.post(["/publicar_anuncio", "/POST_ANUNCIOS_EVENTOS"], async (req, res) => {
  const { TITULO, DESCRIPCION, IMAGEN, P_TITULO, P_DESCRIPCION, P_IMAGEN, P_ID_ESTADO_ANUNCIO_EVENTO } = req.body;
  const tituloFinal = TITULO || P_TITULO;
  const descFinal = DESCRIPCION || P_DESCRIPCION;
  const imgFinal = IMAGEN || P_IMAGEN || null;
  const estadoFinal = P_ID_ESTADO_ANUNCIO_EVENTO || 1;

  if (!tituloFinal || !descFinal) {
    return res.status(400).json({ error: "TITULO y DESCRIPCION son requeridos" });
  }
  try {
    const [result] = await mysqlPool.query(
      `INSERT INTO TBL_ANUNCIOS_EVENTOS (TITULO, DESCRIPCION, IMAGEN, FECHA_HORA, ID_ESTADO_ANUNCIO_EVENTO)
       VALUES (?, ?, ?, NOW(), ?)`,
      [tituloFinal, descFinal, imgFinal, estadoFinal]
    );

    await pushService.notificarGlobal(mysqlPool, {
      titulo: `📢 Nuevo Anuncio: ${tituloFinal}`,
      mensaje: descFinal.length > 100 ? `${descFinal.substring(0, 97)}...` : descFinal,
      tipo: "GLOBAL",
      data: {
        ruta: "/AnunciosEventos",
        idAnuncio: result.insertId
      }
    });

    res.status(201).json({ message: "Anuncio publicado y notificado a toda la comunidad", id: result.insertId });
  } catch (error) {
    console.error("Error al publicar anuncio:", error);
    res.status(500).json({ error: "Error al publicar anuncio" });
  }
});
