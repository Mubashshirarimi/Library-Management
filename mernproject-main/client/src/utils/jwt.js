// Lightweight JWT payload decoder (no signature verification)
export function decodeToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const payload = parts[1];
    // Add padding if needed
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
    const json = atob(padded);
    return JSON.parse(json);
  } catch (err) {
    console.error('Failed to decode token', err);
    return null;
  }
}

export function isTokenExpired(decoded) {
  if (!decoded) return true;
  const now = Date.now() / 1000;
  return !!decoded.exp && decoded.exp < now;
}
