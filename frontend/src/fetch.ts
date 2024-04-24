/* eslint-disable no-var */

export enum HTTPMETHOD {
    GET = "GET",
    HEAD = "HEAD",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    CONNECT = "CONNECT",
    OPTIONS = "OPTIONS",
    TRACE = "TRACE",
    PATCH = "PATCH"
}

const fetchInterceptor = (method: HTTPMETHOD) => (url: string, body: object) => new Promise((resolve, reject) => window.fetch(url, {
    method: method,
    headers: {
        "Content-Type": "application/json",
        Authorization: localStorage.getItem("token") as string
    },
    body: JSON.stringify(body)
})
    .then(async (response) => {
        let data;
        try {
            data = await response.json();
        } catch {
            data = null;
        }

        if (!response.ok) reject({ ok: false, status: response.status, data: data });
        else resolve({ ok: true, status: response.status, data: data });
    })
    .catch((error) => reject(error)));

(window as any).fetch = {
    get: fetchInterceptor(HTTPMETHOD.GET),
    head: fetchInterceptor(HTTPMETHOD.HEAD),
    post: fetchInterceptor(HTTPMETHOD.POST),
    put: fetchInterceptor(HTTPMETHOD.PUT),
    delete: fetchInterceptor(HTTPMETHOD.DELETE),
    connect: fetchInterceptor(HTTPMETHOD.CONNECT),
    options: fetchInterceptor(HTTPMETHOD.OPTIONS),
    trace: fetchInterceptor(HTTPMETHOD.TRACE),
    patch: fetchInterceptor(HTTPMETHOD.PATCH)
};
