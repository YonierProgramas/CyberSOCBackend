export type ErrorCode = 'VALIDATION_FAILED' | 'INVALID_CURSOR' | 'AUTH_REQUIRED' | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED' | 'FORBIDDEN' | 'NOT_FOUND' | 'PROFILE_NOT_FOUND' | 'METHOD_NOT_ALLOWED'
  | 'CONFLICT' | 'POLICY_VERSION_OUTDATED' | 'PAYLOAD_TOO_LARGE' | 'UNSUPPORTED_MEDIA_TYPE'
  | 'RATE_LIMITED' | 'RELEASE_UNAVAILABLE' | 'UPSTREAM_UNAVAILABLE' | 'UPSTREAM_TIMEOUT' | 'INTERNAL';

const messages: Record<ErrorCode, string> = {
  VALIDATION_FAILED: 'La petición contiene datos no válidos.', INVALID_CURSOR: 'Reinicia la lista para continuar.',
  AUTH_REQUIRED: 'Debes iniciar sesión.', TOKEN_INVALID: 'La sesión no es válida.',
  TOKEN_EXPIRED: 'Tu sesión venció. Vuelve a entrar.', FORBIDDEN: 'No tienes permiso para esta operación.',
  NOT_FOUND: 'El recurso no existe.', PROFILE_NOT_FOUND: 'Debes crear tu perfil.',
  METHOD_NOT_ALLOWED: 'Método no permitido.', CONFLICT: 'El estado del recurso cambió.',
  POLICY_VERSION_OUTDATED: 'Debes revisar la versión vigente antes de conceder permiso.',
  PAYLOAD_TOO_LARGE: 'La petición supera el tamaño permitido.', UNSUPPORTED_MEDIA_TYPE: 'Se requiere JSON UTF-8.',
  RATE_LIMITED: 'Espera antes de volver a intentarlo.', RELEASE_UNAVAILABLE: 'Instalador pendiente.',
  UPSTREAM_UNAVAILABLE: 'El servicio de datos no está disponible.', UPSTREAM_TIMEOUT: 'El servicio de datos tardó demasiado.',
  INTERNAL: 'No se pudo completar la operación.',
};

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: ErrorCode,
    public readonly headers: Record<string, string> = {}) { super(messages[code]); }
}
export const invalid = () => new ApiError(400, 'VALIDATION_FAILED');
export const unavailable = () => new ApiError(503, 'UPSTREAM_UNAVAILABLE');
export function requireValid<T>(result: { success: true; data: T } | { success: false }): T {
  if (!result.success) throw invalid();
  return result.data;
}
