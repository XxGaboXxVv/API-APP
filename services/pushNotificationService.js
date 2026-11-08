const fs = require('fs');
const path = require('path');
const { initializeApp, cert } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');

let firebaseApp = null;
let messagingInstance = null;

try {
  let serviceAccount = null;
  const envKey = process.env.FIREBASE_SERVICE_ACCOUNT;
  const customPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
  const defaultPath = path.join(__dirname, '..', 'serviceAccountKey.json');
  const renderSecretPath = '/etc/secrets/serviceAccountKey.json';

  if (envKey) {
    try {
      serviceAccount = JSON.parse(envKey);
    } catch {
      try {
        const decoded = Buffer.from(envKey, 'base64').toString('utf8');
        serviceAccount = JSON.parse(decoded);
      } catch (err) {
        console.error('Error al parsear FIREBASE_SERVICE_ACCOUNT:', err.message);
      }
    }
  } else if (customPath && fs.existsSync(customPath)) {
    serviceAccount = JSON.parse(fs.readFileSync(customPath, 'utf8'));
  } else if (fs.existsSync(defaultPath)) {
    serviceAccount = JSON.parse(fs.readFileSync(defaultPath, 'utf8'));
  } else if (fs.existsSync(renderSecretPath)) {
    serviceAccount = JSON.parse(fs.readFileSync(renderSecretPath, 'utf8'));
  }

  if (serviceAccount) {
    firebaseApp = initializeApp({
      credential: cert(serviceAccount)
    });
    messagingInstance = getMessaging(firebaseApp);
    console.log('Firebase Admin inicializado correctamente');
  } else {
    console.log('Credenciales de Firebase no encontradas. Las notificaciones se guardaran en base de datos.');
  }
} catch (error) {
  console.error('Error al inicializar Firebase Admin:', error.message);
}

async function guardarTokenDispositivo(mysqlPool, usuarioId, fcmToken, plataforma = 'Android') {
  if (!usuarioId || !fcmToken) return;
  const sql = `
    INSERT INTO TBL_USUARIO_DISPOSITIVOS (ID_USUARIO, FCM_TOKEN, PLATAFORMA, FECHA_ACTUALIZACION)
    VALUES (?, ?, ?, NOW())
    ON DUPLICATE KEY UPDATE 
      ID_USUARIO = VALUES(ID_USUARIO),
      PLATAFORMA = VALUES(PLATAFORMA),
      FECHA_ACTUALIZACION = NOW()
  `;
  await mysqlPool.query(sql, [usuarioId, fcmToken, plataforma]);
}

async function registrarEnBaseDeDatos(mysqlPool, usuarioId, { titulo, mensaje, tipo, data }) {
  const datosExtra = data ? JSON.stringify(data) : null;
  const sql = `
    INSERT INTO TBL_NOTIFICACIONES (ID_USUARIO, TITULO, MENSAJE, TIPO, LEIDO, DATOS_EXTRA, FECHA_CREACION)
    VALUES (?, ?, ?, ?, 0, ?, NOW())
  `;
  const [result] = await mysqlPool.query(sql, [usuarioId, titulo, mensaje, tipo, datosExtra]);
  return result.insertId;
}

async function despacharFCM(mysqlPool, tokens, { titulo, mensaje, data }) {
  if (!messagingInstance || !tokens || tokens.length === 0) return;

  const payloadData = {
    title: String(titulo || ''),
    body: String(mensaje || ''),
    tipo: String(data?.tipo || 'GENERAL'),
  };
  if (data && typeof data === 'object') {
    for (const key of Object.keys(data)) {
      payloadData[key] = String(data[key]);
    }
  }

  const message = {
    notification: {
      title: titulo,
      body: mensaje,
    },
    data: payloadData,
    android: {
      priority: 'high',
      notification: {
        sound: 'default',
        channelId: 'acacias_high_importance_channel',
        priority: 'max',
      },
    },
    tokens: tokens,
  };

  try {
    const response = await messagingInstance.sendEachForMulticast(message);
    if (response.failureCount > 0) {
      const tokensAEliminar = [];
      response.responses.forEach((resp, idx) => {
        if (!resp.success) {
          const errCode = resp.error?.code;
          if (
            errCode === 'messaging/invalid-registration-token' ||
            errCode === 'messaging/registration-token-not-registered'
          ) {
            tokensAEliminar.push(tokens[idx]);
          }
        }
      });
      if (tokensAEliminar.length > 0) {
        await mysqlPool.query(
          'DELETE FROM TBL_USUARIO_DISPOSITIVOS WHERE FCM_TOKEN IN (?)',
          [tokensAEliminar]
        );
      }
    }
  } catch (error) {
    console.error('Error al enviar notificación FCM multicast:', error.message);
  }
}

async function notificarUsuario(mysqlPool, usuarioId, { titulo, mensaje, tipo = 'GENERAL', data = {}, soloPush = false }) {
  if (!usuarioId) return;
  try {
    if (!soloPush) {
      await registrarEnBaseDeDatos(mysqlPool, usuarioId, { titulo, mensaje, tipo, data });
    }
    const [rows] = await mysqlPool.query(
      'SELECT FCM_TOKEN FROM TBL_USUARIO_DISPOSITIVOS WHERE ID_USUARIO = ?',
      [usuarioId]
    );
    const tokens = rows.map(r => r.FCM_TOKEN).filter(Boolean);
    if (tokens.length > 0) {
      await despacharFCM(mysqlPool, tokens, { titulo, mensaje, data: { ...data, tipo } });
    }
  } catch (error) {
    console.error(`Error en notificarUsuario(${usuarioId}):`, error.message);
  }
}

async function notificarRoles(mysqlPool, roles, { titulo, mensaje, tipo = 'GENERAL', data = {} }) {
  if (!roles || !Array.isArray(roles) || roles.length === 0) return;
  try {
    const [rows] = await mysqlPool.query(
      'SELECT DISTINCT ID_USUARIO FROM TBL_MS_USUARIO WHERE ID_ROL IN (?) AND ID_ESTADO_USUARIO = 1',
      [roles]
    );
    for (const r of rows) {
      await notificarUsuario(mysqlPool, r.ID_USUARIO, { titulo, mensaje, tipo, data });
    }
  } catch (error) {
    console.error('Error en notificarRoles:', error.message);
  }
}

async function notificarAdminCondominio(mysqlPool, idCondominio, { titulo, mensaje, tipo = 'FAMILIA', data = {} }) {
  if (!idCondominio) return;
  try {
    const [adminRows] = await mysqlPool.query(
      `SELECT u.ID_USUARIO 
       FROM TBL_PERSONAS p
       JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
       WHERE p.ID_CONDOMINIO = ? AND p.ID_PADRE = 1`,
      [idCondominio]
    );
    for (const adminUser of adminRows) {
      await notificarUsuario(mysqlPool, adminUser.ID_USUARIO, { titulo, mensaje, tipo, data });
    }
  } catch (error) {
    console.error(`Error en notificarAdminCondominio(${idCondominio}):`, error.message);
  }
}

async function notificarEntregaVivienda(mysqlPool, idCondominio, idResidenteReceptor, { titulo, mensaje, data = {} }) {
  try {
    const usuariosObjetivo = new Set();
    if (idResidenteReceptor) {
      usuariosObjetivo.add(idResidenteReceptor);
    }
    if (idCondominio) {
      const [adminRows] = await mysqlPool.query(
        `SELECT u.ID_USUARIO 
         FROM TBL_PERSONAS p
         JOIN TBL_MS_USUARIO u ON u.NOMBRE_USUARIO COLLATE utf8mb4_general_ci = p.NOMBRE_PERSONA COLLATE utf8mb4_general_ci
         WHERE p.ID_CONDOMINIO = ? AND p.ID_PADRE = 1`,
        [idCondominio]
      );
      adminRows.forEach(r => usuariosObjetivo.add(r.ID_USUARIO));
    }

    for (const uid of usuariosObjetivo) {
      await notificarUsuario(mysqlPool, uid, {
        titulo,
        mensaje,
        tipo: 'PAQUETE_ENTREGA',
        data
      });
    }
  } catch (error) {
    console.error('Error en notificarEntregaVivienda:', error.message);
  }
}

async function notificarGlobal(mysqlPool, { titulo, mensaje, tipo = 'GLOBAL', data = {} }) {
  try {
    const [usuarios] = await mysqlPool.query(
      'SELECT DISTINCT ID_USUARIO FROM TBL_MS_USUARIO WHERE ID_ESTADO_USUARIO = 1'
    );
    for (const user of usuarios) {
      await registrarEnBaseDeDatos(mysqlPool, user.ID_USUARIO, { titulo, mensaje, tipo, data });
    }
    const [tokenRows] = await mysqlPool.query(
      'SELECT DISTINCT FCM_TOKEN FROM TBL_USUARIO_DISPOSITIVOS'
    );
    const tokens = tokenRows.map(r => r.FCM_TOKEN).filter(Boolean);
    if (tokens.length > 0) {
      for (let i = 0; i < tokens.length; i += 500) {
        const batch = tokens.slice(i, i + 500);
        await despacharFCM(mysqlPool, batch, { titulo, mensaje, data: { ...data, tipo } });
      }
    }
  } catch (error) {
    console.error('Error en notificarGlobal:', error.message);
  }
}

module.exports = {
  guardarTokenDispositivo,
  notificarUsuario,
  notificarRoles,
  notificarAdminCondominio,
  notificarEntregaVivienda,
  notificarGlobal,
};
