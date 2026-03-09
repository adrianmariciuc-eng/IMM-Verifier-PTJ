// PUT /api/admin/users/:id/password - Change password
export async function onRequestPut(context) {
    const { request, env, data, params } = context;
    const { hashPassword, generateSalt } = data;
    const userId = parseInt(params.id);

    let body;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: 'Request invalid.' }, { status: 400 });
    }

    const { password } = body;
    if (!password || password.length < 4) {
        return Response.json({ error: 'Parola trebuie sa aiba minim 4 caractere.' }, { status: 400 });
    }

    const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
    if (!user) {
        return Response.json({ error: 'Utilizatorul nu exista.' }, { status: 404 });
    }

    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    await env.DB.prepare(
        'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?'
    ).bind(hash, salt, userId).run();

    // Invalidate all sessions for this user
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();

    return Response.json({ ok: true });
}
