export async function onRequestPost(context) {
    const { env, data } = context;
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(data.token).run();
    return Response.json({ ok: true });
}
