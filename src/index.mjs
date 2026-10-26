import { createApiServer } from './server.mjs';

const port = Number(process.env.PORT ?? 3001);
const host = process.env.HOST ?? '127.0.0.1';
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT debe ser un entero entre 1 y 65535.');
}
const server = createApiServer();
server.listen(port, host, () => console.log(`CyberSOC API disponible en http://${host}:${port}`));
server.on('error', () => {
  console.error('No se pudo iniciar la API. Revisa puerto y dirección de escucha.');
  process.exitCode = 1;
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  });
}
