# TruthGate

> The Secure, Self-Hosted Edge Gateway IPFS Always Needed — with Logins, API Keys, GUI Control, and Web3 Site Publishing.

**TruthGate** makes it easy to run a fully secured IPFS node on your own terms — complete with user logins, API key management, GUI tools, and seamless site publishing. Whether you’re deploying from your LAN or a VPS, TruthGate wraps powerful IPFS functionality in a clean, hardened interface you can actually trust.

Blazing-fast. Web3 native. Web2 compatible. Fully open source.

---

## ✨ Features at a Glance

- 🔐 **Secure User Logins** – Lock down access with role-based accounts.
- 🔑 **API Key Management** – Authenticate programmatic access with scoped tokens.
- 🧭 **Clean GUI** – Manage users, routes, domains, and publishing in minutes.
- ⚡ **/ipfs/ + /webui/ Access** – Retain native IPFS routing & control with access control.
- 🌐 **Auto SSL & Domain Linking** – Set a custom domain, get instant HTTPS.
- 🚀 **Drag-and-Drop Site Publishing** – Deploy Web3/Wasmtime/Blazor/SPA sites in seconds.
- 💥 **Web2/Web3 Hybrid Hosting** – Serve modern apps to both IPFS-native and traditional users.
- 🛡️ **Edge Gateway Hardened** – IPFS node exposure without security nightmares.

---

## 🔧 What Is It?

TruthGate is a **secure edge layer for IPFS nodes**. It wraps your local or remote IPFS instance in a hardened, user-authenticated environment with optional GUI and domain support. 

Think **Netlify, but for IPFS.**  
Self-hosted. Decentralized. Login-protected. Actually yours.

---

## How To Get Started

> Coming soon

---

## 🧱 Architecture Overview

TruthGate includes:

* A hardened **Kestrel reverse proxy** for TLS handling and certificate negotiation (via Let’s Encrypt or Cloudflare).
* A web management layer with **role-based user accounts and token issuance**.
* A publish flow that can **detect new domains**, configure SSL, and serve directly from your IPFS node.
* Full support for **API passthrough** to `/api/v0/` with optional proxy scoping.

---

## 💭 Why TruthGate?

Deploying IPFS-based sites should be easier than it is.

Most devs hit walls with:

* IPFS node exposure risks
* SSL and domain linking headaches
* CLI-only publishing
* Zero protection for /api or /webui routes
* CDN dependency or reliance on IPFS.io pinning

TruthGate fixes these problems by giving you a **clean, self-hosted publishing experience** that behaves like the tools you love — but without centralization.

---

## 🧪 Web3 Publishing Made Easy

TruthGate supports:

* 📦 **WASM, Blazor, Svelte, React, Vue** — if it compiles to static, it works.
* 🛠️ **Drag-and-Drop Uploads** (GUI), or CLI-based deployment (coming soon)
* 🌍 **Auto domain recognition** and **HTTPS certificate generation**
* 💡 Optional **Cloudflare integration** for subdomain proxying

Whether you're deploying from CI/CD or your local machine, publishing to IPFS is finally *easy and secure*.


---

## ❤️ A Note from the Creator

I built this out of frustration.

I wanted a way to serve Web3-native apps that *actually worked* — securely, reliably, and without selling my soul to some centralized host. And now… it's real.

If you’ve ever wrestled with IPFS routing, SSL certs, or gateway hacks just to get your site online — **TruthGate is for you.**

---

## 📖 License

TruthGate is licensed under the MIT License.
Use it. Fork it. Break it. Improve it. Let it spread.

---

## 🧙‍♂️ Contribute

Pull requests welcome.
Stars encourage me.
Issues are sacred.

Let's fix decentralized hosting — together.
