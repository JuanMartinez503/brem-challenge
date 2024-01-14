// pages/api/login.ts

import { lucia } from "../../auth";
import { Argon2id } from "oslo/password";
import db from '../../utils/db';
import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
    const formData = await context.request.formData();
    const username = formData.get("username");
    const password = formData.get("password");

    if (
        typeof username !== "string" ||
        username.length < 3 ||
        username.length > 31 ||
        !/^[a-z0-9_-]+$/.test(username)
    ) {
        return new Response("Invalid username", {
            status: 400
        });
    }

    if (typeof password !== "string" || password.length < 6 || password.length > 255) {
        return new Response("Invalid password", {
            status: 400
        });
    }

    const existingUser = await db.user.findFirst({
        where: {
            username: username
        }
    });

    if (!existingUser) {
        return new Response("Incorrect username or password", {
            status: 400
        });
    }

    const validPassword = await new Argon2id().verify(existingUser.hashed_password, password);

    if (!validPassword) {
        return new Response("Incorrect username or password", {
            status: 400
        });
    }

    const session = await lucia.createSession(existingUser.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    context.cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

    console.log('Login was successful!');
    
    return context.redirect("/");
}
