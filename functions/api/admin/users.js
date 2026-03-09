// GET /api/admin/users - List all users
export async function onRequestGet(context) {
    const { env } = context;
    const { results } = await env.DB.prepare(
        'SELECT id, username, role, created_at FROM users ORDER BY id'
    ).all();
    return Response.json({ users: results });
}

// POST /api/admin/users - Create new user
export async function onRequestPost(context) {
    const { request, env, data } = context;
    const { hashPassword, generateSalt } = data;

    let body;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: 'Request invalid.' }, { status: 400 });
    }

    const { username, password, role } = body;

    if (!username || !username.trim()) {
        return Response.json({ error: 'Username-ul este obligatoriu.' }, { status: 400 });
    }
    if (!password || password.length < 4) {
        return Response.json({ error: 'Parola trebuie sa aiba minim 4 caractere.' }, { status: 400 });
    }
    if (role && !['admin', 'user'].includes(role)) {
        return Response.json({ error: 'Rolul trebuie sa fie "admin" sau "user".' }, { status: 400 });
    }

    // Check uniqueness
    const existing = await env.DB.prepare(
        'SELECT id FROM users WHERE username = ? COLLATE NOCASE'
    ).bind(username.trim()).first();
    if (existing) {
        return Response.json({ error: 'Acest username exista deja.' }, { status: 409 });
    }

    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await env.DB.prepare(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)'
    ).bind(username.trim(), hash, salt, role || 'user').run();

    const newUser = await env.DB.prepare(
        'SELECT id, username, role, created_at FROM users WHERE id = ?'
    ).bind(result.meta.last_row_id).first();

    return Response.json({ user: newUser }, { status: 201 });
}
