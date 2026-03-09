// PUT /api/admin/users/:id/role - Change role
export async function onRequestPut(context) {
    const { request, env, data, params } = context;
    const userId = parseInt(params.id);

    if (userId === data.user.id) {
        return Response.json({ error: 'Nu va puteti schimba propriul rol.' }, { status: 400 });
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error: 'Request invalid.' }, { status: 400 });
    }

    const { role } = body;
    if (!['admin', 'user'].includes(role)) {
        return Response.json({ error: 'Rolul trebuie sa fie "admin" sau "user".' }, { status: 400 });
    }

    const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
    if (!user) {
        return Response.json({ error: 'Utilizatorul nu exista.' }, { status: 404 });
    }

    await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, userId).run();

    return Response.json({ ok: true });
}
