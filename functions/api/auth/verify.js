export async function onRequestGet(context) {
    const { data } = context;
    return Response.json({ user: data.user });
}
