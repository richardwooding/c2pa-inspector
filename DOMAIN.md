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
2. `echo c2pa-inspector.dev > site/CNAME`
3. Replace the host everywhere:
   `grep -rl 'richardwooding.github.io/c2pa-inspector/' site/ | xargs sed -i '' 's|https://richardwooding.github.io/c2pa-inspector/|https://c2pa-inspector.dev/|g'`
   That covers `index.html` (canonical, `og:url`, `og:image`, `twitter:image`,
   the JSON-LD `url`), `sitemap.xml` and `robots.txt`.
4. Enable **Enforce HTTPS** in the repo's Pages settings once the certificate
   is issued (it can take a few minutes after DNS propagates).
5. Re-submit `sitemap.xml` in Search Console under the new property.

The old github.io URL keeps working afterwards — GitHub redirects it to the
custom domain, so existing links and any accrued ranking follow.
