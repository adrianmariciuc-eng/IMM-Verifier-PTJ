// Shared crypto utilities
async function hashPassword(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const hashBuffer = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        256
    );
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function generateSalt() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSessionToken() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Bootstrap: create tables and seed admin if needed
let bootstrapped = false;
let bootstrapping = null;
async function bootstrap(env) {
    if (bootstrapped) return;
    if (bootstrapping) return bootstrapping;
    bootstrapping = _bootstrap(env);
    return bootstrapping;
}
async function _bootstrap(env) {
    try {
        await env.DB.prepare('SELECT 1 FROM users LIMIT 1').first();
    } catch {
        // Tables don't exist yet - create them one by one
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')), created_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`).run();
        await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`).run();
        await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`).run();
    }
    // Seed admin if no users exist
    const count = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first('c');
    if (count === 0) {
        const salt = generateSalt();
        const hash = await hashPassword('M@ra2@23', salt);
        await env.DB.prepare(
            'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)'
        ).bind('adrian.mariciuc', hash, salt, 'admin').run();
    }
    bootstrapped = true;
}

// Auth middleware
async function authMiddleware(context) {
    const { request, env, next, data } = context;
    const url = new URL(request.url);

    // Bootstrap DB on first request
    await bootstrap(env);

    // Attach crypto utils to context data
    data.hashPassword = hashPassword;
    data.generateSalt = generateSalt;
    data.generateSessionToken = generateSessionToken;

    // Skip auth for login endpoint
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        return next();
    }

    // All other API routes require auth
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return Response.json({ error: 'Neautorizat.' }, { status: 401 });
    }

    const token = authHeader.slice(7);
    const session = await env.DB.prepare(`
        SELECT s.*, u.id as user_id, u.username, u.role
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.id = ? AND s.expires_at > datetime('now')
    `).bind(token).first();

    if (!session) {
        return Response.json({ error: 'Sesiune invalida sau expirata.' }, { status: 401 });
    }

    data.user = { id: session.user_id, username: session.username, role: session.role };
    data.token = token;

    // Admin-only routes
    if (url.pathname.startsWith('/api/admin/') && session.role !== 'admin') {
        return Response.json({ error: 'Acces interzis.' }, { status: 403 });
    }

    return next();
}

export const onRequest = [authMiddleware];
