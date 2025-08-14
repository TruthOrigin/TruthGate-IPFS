// sw.js
self.addEventListener("install", (evt) => {
  // Skip waiting so it takes control faster (optional)
  self.skipWaiting();
});

self.addEventListener("activate", (evt) => {
  // Become the controller for open clients immediately (optional)
  evt.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (evt) => {
  const req = evt.request;

  // Only handle same-origin
  const url = new URL(req.url);
  const sameOrigin = url.origin === self.location.origin;

  // We only care about your protected gateway paths
  const isIpfs = sameOrigin && url.pathname.startsWith("/ipfs/");

  if (!isIpfs) return; // let the browser do its thing

  // Recreate the Request but force credentials to include cookies.
  // Note: you cannot set the Cookie header yourself.
  const withCreds = new Request(req, { credentials: "include" });

  evt.respondWith(
    fetch(withCreds).then((res) => {
      // Optional: if your server issues redirects with absolute 127.0.0.1 URLs,
      // normalize Location back to our origin:
      const loc = res.headers.get("Location");
      if (loc && sameOrigin === true) {
        try {
          const locUrl = new URL(loc, url.origin);
          if (locUrl.origin !== url.origin && (locUrl.hostname === "127.0.0.1" || locUrl.hostname === "localhost")) {
            // Rewrite is server-side ideally, but you could proxy via SW if needed.
          }
        } catch {}
      }
      return res;
    }).catch((err) => {
      // Optional fallback
      return new Response("Network error", { status: 502 });
    })
  );
});
