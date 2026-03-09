// DELETE /api/admin/users/:id - Remove user
export async function onRequestDelete(context) {
    const { env, data, params } = context;
    const userId = parseInt(params.id);

    if (userId === data.user.id) {
        return Response.json({ error: 'Nu va puteti sterge propriul cont.' }, { status: 400 });
    }

    const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
    if (!user) {
        return Response.json({ error: 'Utilizatorul nu exista.' }, { status: 404 });
    }

    // Delete sessions first, then user
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

    return Response.json({ ok: true });
}
