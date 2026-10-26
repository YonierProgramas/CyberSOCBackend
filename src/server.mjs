import { createServer } from 'node:http';

// Base de transporte: todavía no implementa identidad ni conexión a Supabase.
export function createApiServer() {
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');

    const pathname = request.url?.split('?')[0];
    if (pathname === '/healthz') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405, { Allow: 'GET, HEAD' });
        response.end(JSON.stringify({ error: { code: 'METHOD_NOT_ALLOWED', message: 'Método no permitido.' } }));
        return;
      }
      response.writeHead(200);
      response.end(request.method === 'HEAD' ? undefined : JSON.stringify({
        service: 'cybersoc-api', status: 'ok', stage: 'foundation',
        capabilities: { authentication: false, database: false },
      }));
      return;
    }

    response.writeHead(404);
    response.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'La ruta no existe.' } }));
  });
  server.headersTimeout = 8000;
  server.requestTimeout = 10000;
  server.maxRequestsPerSocket = 100;
  return server;
}
