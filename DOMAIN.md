# Switching to a custom domain

The site is built for `c2pa-inspector.dev` but currently ships with
`richardwooding.github.io/c2pa-inspector/` in every absolute URL, because a
`CNAME` file takes effect the moment it lands: GitHub Pages starts redirecting
to the custom domain, and until DNS resolves the site is simply down. A
canonical tag pointing at a domain that does not resolve is worse than none —
search engines drop the page rather than wait.

When the domain is registered, in one commit:

1. Point DNS at GitHub Pages — four `A` records for the apex
   (`185.199.108.153`, `.109.153`, `.110.153`, `.111.153`), or a `CNAME` to
   `richardwooding.github.io.` if using a subdomain.
2. **Set the custom domain as a repo setting, not a file.** This repo deploys
   Pages from a workflow (`build_type: workflow`), and in that mode a `CNAME`
   file inside the uploaded artifact is inert — GitHub only reads one when Pages
   builds from a branch. The deploy will succeed and the domain will simply
   never take effect. Set it with:
   `gh api -X PUT repos/richardwooding/c2pa-inspector/pages -f cname=c2pa-inspector.dev`
   (or Settings → Pages → Custom domain). Keep `site/CNAME` anyway: GitHub
   writes one into the published site, and it documents the intent in the repo.
3. Replace the host everywhere:
   `grep -rl 'richardwooding.github.io/c2pa-inspector/' site/ | xargs sed -i '' 's|https://richardwooding.github.io/c2pa-inspector/|https://c2pa-inspector.dev/|g'`
   That covers `index.html` (canonical, `og:url`, `og:image`, `twitter:image`,
   the JSON-LD `url`), `sitemap.xml` and `robots.txt`.
4. Enable **Enforce HTTPS** once the certificate is issued — watch
   `gh api repos/richardwooding/c2pa-inspector/pages --jq .https_certificate.state`
   go `authorization_created` → `issued`, which takes a few minutes. On a `.dev`
   domain this is not optional: the TLD is HSTS-preloaded, so browsers refuse
   plain HTTP and the site is unreachable until the certificate is live.
   If Cloudflare is the DNS host, the records must stay **DNS-only (grey
   cloud)** — a proxied record makes Cloudflare answer the ACME challenge and
   GitHub can never issue the certificate.
5. Re-submit `sitemap.xml` in Search Console under the new property.

The old github.io URL keeps working afterwards — GitHub redirects it to the
custom domain, so existing links and any accrued ranking follow.
