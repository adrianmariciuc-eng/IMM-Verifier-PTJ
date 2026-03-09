export async function onRequestPost(context) {
    const { request, env, data } = context;
    const { hashPassword, generateSalt, generateSessionToken } = data;

    let body;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: 'Request invalid.' }, { status: 400 });
    }

    const { username, password } = body;
    if (!username || !password) {
        return Response.json({ error: 'Username si parola sunt obligatorii.' }, { status: 400 });
    }

    // Look up user
    const user = await env.DB.prepare(
        'SELECT * FROM users WHERE username = ? COLLATE NOCASE'
    ).bind(username).first();

    if (!user) {
        return Response.json({ error: 'Utilizator sau parola incorecta.' }, { status: 401 });
    }

    // Verify password
    const hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash) {
        return Response.json({ error: 'Utilizator sau parola incorecta.' }, { status: 401 });
    }

    // Create session (7 days expiry)
    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare(
        'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, user.id, expiresAt).run();

    // Clean expired sessions (async, non-blocking)
    await env.DB.prepare('DELETE FROM sessions WHERE expires_at < datetime("now")').run();

    return Response.json({
        token,
        user: { id: user.id, username: user.username, role: user.role }
    });
}
