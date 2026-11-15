# MZL Solution — company website

Static website (plain HTML/CSS/JS) for **mzlsolution.com**, built to bring in clients through WhatsApp and email.

## Configuration
In `index.html`, near the end of the file (`CONFIG` block):
- `WHATSAPP`: country code + number, digits only (currently `13213522627`)
- `WA_LABEL`: formatted number shown on the page
- Contact email: `mzl@mzlsolution.com`

## Publish (GitHub Pages — free)
1. Repo → **Settings → Pages** → Source: *Deploy from a branch* → `main` / `(root)`.
2. The `CNAME` file already points to `mzlsolution.com`.
3. In your domain's DNS settings, create:
   - 4 **A** records for `@`: `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - 1 **CNAME** record for `www` → `YOUR-USERNAME.github.io`
4. Once DNS propagates, enable **Enforce HTTPS** under Settings → Pages.

## Getting clients
- Create a **Google Business Profile** (business.google.com) and link the site.
- Submit the site to **Google Search Console** with `https://mzlsolution.com/sitemap.xml`.
- Add the link to your Instagram/LinkedIn bio and WhatsApp Business profile.
