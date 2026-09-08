import { defineConfig } from 'vitepress'
import { readFileSync } from 'node:fs'

// Single source of truth for the version shown in the nav: read it from
// Cargo.toml at build time so the docs can never drift from the crate again.
const version =
  readFileSync(new URL('../../Cargo.toml', import.meta.url), 'utf-8')
    .match(/^version\s*=\s*"([^"]+)"/m)?.[1] ?? '0.0.0'

export default defineConfig({
  title: 'Zion Edge Gateway',
  description: 'High-performance TLS reverse proxy with built-in WAF, written in Rust',
  base: '/zion/',
  // The hostname must carry the base path: VitePress joins it with each page's
  // route, so without /zion/ every URL in the sitemap points at a 404.
  sitemap: { hostname: 'https://fabriziosalmi.github.io/zion/' },
  head: [
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/zion/logo.svg' }],
    // Apple / PWA touch icon (raster; SVG is not honoured here).
    ['link', { rel: 'apple-touch-icon', href: '/zion/apple-touch-icon.png' }],
    ['meta', { name: 'theme-color', content: '#0b0b0d' }],
    // Let Google Discover use large image previews.
    ['meta', { name: 'robots', content: 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1' }],
    ['meta', { property: 'og:title', content: 'Zion Edge Gateway' }],
    ['meta', { property: 'og:description', content: 'One auditable Rust binary at the edge — TLS 1.3, a zero-regex WAF, and a two-level RAM cache. No sidecars, no control plane.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Zion Edge Gateway' }],
    // Absolute URL, 1200×630, served from this site (docs/public/og.png).
    ['meta', { property: 'og:image', content: 'https://fabriziosalmi.github.io/zion/og.png' }],
    ['meta', { property: 'og:image:width', content: '1200' }],
    ['meta', { property: 'og:image:height', content: '630' }],
    ['meta', { property: 'og:image:alt', content: 'Zion Edge Gateway — TLS 1.3, a zero-regex WAF, and a two-level RAM cache' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: 'Zion Edge Gateway' }],
    ['meta', { name: 'twitter:description', content: 'One auditable Rust binary at the edge — TLS 1.3, a zero-regex WAF, and a two-level RAM cache. No sidecars, no control plane.' }],
    ['meta', { name: 'twitter:image', content: 'https://fabriziosalmi.github.io/zion/og.png' }],
    // Structured data for search + AI crawlers (Schema.org). WebSite +
    // SoftwareApplication describe the project as a free, cross-platform
    // developer tool; emitted site-wide so any entry page carries it.
    [
      'script',
      { type: 'application/ld+json' },
      JSON.stringify({
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'WebSite',
            name: 'Zion Edge Gateway',
            url: 'https://fabriziosalmi.github.io/zion/',
            description:
              'High-performance TLS reverse proxy with built-in WAF, written in Rust.',
          },
          {
            '@type': 'SoftwareApplication',
            name: 'Zion Edge Gateway',
            description:
              'High-performance TLS reverse proxy with built-in WAF, written in Rust.',
            url: 'https://fabriziosalmi.github.io/zion/',
            applicationCategory: 'DeveloperApplication',
            operatingSystem: 'Linux, macOS, Windows',
            programmingLanguage: 'Rust',
            license: 'https://www.apache.org/licenses/LICENSE-2.0',
            codeRepository: 'https://github.com/fabriziosalmi/zion',
            downloadUrl: 'https://github.com/fabriziosalmi/zion/releases',
            author: {
              '@type': 'Person',
              name: 'Fabrizio Salmi',
              url: 'https://github.com/fabriziosalmi',
            },
            offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
          },
        ],
      }),
    ],
  ],

  lastUpdated: true,
  cleanUrls: true,

  // Per-page absolute canonical + og:url. VitePress emits neither by default,
  // so build the URL from the page's own path against the canonical origin.
  // cleanUrls is on, so `foo/bar.md` → `foo/bar` and any `index.md` → the
  // directory with a trailing slash — matching the generated sitemap exactly.
  transformPageData(pageData) {
    const origin = 'https://fabriziosalmi.github.io/zion/'
    const slug = pageData.relativePath
      .replace(/(^|\/)index\.md$/, '$1')
      .replace(/\.md$/, '')
    const url = origin + slug
    pageData.frontmatter.head ??= []
    pageData.frontmatter.head.push(
      ['link', { rel: 'canonical', href: url }],
      ['meta', { property: 'og:url', content: url }],
    )
  },

  // Internal working notes (homelab topology, bench-rig hosts) are gitignored
  // and must never render on the public site even if present in a local tree.
  srcExclude: ['internal/**'],

  // Many docs (security/asvs.md, perf/roadmap.md, the ADRs) deep-link
  // to source files outside the docs/ tree (e.g. ../../src/dispatch.rs,
  // ../../deny.toml, ../../CHANGELOG). VitePress's dead-link checker
  // doesn't follow paths outside the docs root and flags every such
  // reference as broken — even though the files exist on the same
  // commit and resolve correctly when the rendered HTML is browsed
  // via the GitHub source view. Skip these patterns; internal-only
  // docs cross-links remain checked.
  ignoreDeadLinks: [
    // Anything that walks up out of the docs tree (matches both
    // `../../...` and `./../../...` shapes used across the docs).
    /\.\.\/\.\.\//,
    // Sibling directory hops that reach a doc index that's only
    // referenced as `index` without an extension (e.g. `./../adr/index`).
    /\/index$/,
    // Bare repo-root files referenced from any depth.
    /\/(SECURITY|CHANGELOG|README|Dockerfile|deny\.toml|rust-toolchain\.toml)$/,
  ],

  themeConfig: {
    // Object form (not a bare string) so VitePress renders a non-empty `alt`
    // on the nav logo instead of `alt=""` — the site's only <img>.
    logo: { src: '/logo.svg', alt: 'Zion Edge Gateway logo' },
    siteTitle: 'Zion',

    nav: [
      { text: 'Guide', link: '/guide/' },
      { text: 'Config', link: '/config/' },
      { text: 'Security', link: '/security/' },
      {
        text: 'Performance',
        items: [
          { text: 'Benchmarks', link: '/benchmarks/' },
          { text: 'Optimization Log', link: '/benchmarks/optimization' },
        ]
      },
      {
        text: `v${version}`,
        items: [
          { text: 'Changelog', link: 'https://github.com/fabriziosalmi/zion/blob/master/CHANGELOG.md' },
          { text: 'Releases', link: 'https://github.com/fabriziosalmi/zion/releases' },
        ]
      },
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is Zion?', link: '/guide/' },
          { text: 'Quick Start', link: '/guide/quickstart' },
          { text: 'Migrating to Zion', link: '/guide/migrate' },
          { text: 'CLI reference', link: '/guide/cli' },
          { text: 'Architecture', link: '/guide/architecture' },
        ]
      },
      {
        text: 'Configuration',
        items: [
          { text: 'Reference', link: '/config/' },
          { text: 'TLS & SNI', link: '/config/tls' },
          { text: 'ACME (auto-renewal)', link: '/config/acme' },
          { text: 'Routing', link: '/config/routing' },
          { text: 'Caching', link: '/config/caching' },
          { text: 'WAF', link: '/config/waf' },
          { text: 'CORS', link: '/config/cors' },
          { text: 'Authentication', link: '/config/auth' },
          { text: 'HTTP/3 (QUIC)', link: '/config/http3' },
          { text: 'Sovereign Edge', link: '/config/sovereign' },
        ]
      },
      {
        text: 'Security',
        items: [
          { text: 'WAF pipeline', link: '/security/' },
          { text: 'Hardening', link: '/security/hardening' },
          { text: 'Threat model (STRIDE)', link: '/security/threat-model' },
          { text: 'OWASP ASVS L2', link: '/security/asvs' },
          { text: 'Compliance mapping', link: '/security/compliance-mapping' },
          { text: 'FIPS 140-3', link: '/security/fips' },
          { text: 'TLS conformance', link: '/security/tls-conformance' },
          { text: 'Supply chain', link: '/security/supply-chain' },
        ]
      },
      {
        text: 'Performance',
        items: [
          { text: 'Benchmarks', link: '/benchmarks/' },
          { text: 'Optimization log', link: '/benchmarks/optimization' },
          { text: 'Microbenchmarks', link: '/perf/microbench' },
          { text: 'PGO build', link: '/perf/pgo' },
          { text: 'Mesh overhead', link: '/perf/mesh-overhead' },
          { text: 'Roadmap', link: '/perf/roadmap' },
        ]
      },
      {
        text: 'Operations',
        items: [
          { text: 'Deployment', link: '/deploy/' },
          { text: 'Monitoring (Prometheus/Grafana)', link: '/deploy/observability' },
          { text: 'Observability internals', link: '/guide/observability' },
          { text: 'Hot-reload', link: '/deploy/hot-reload' },
          { text: 'Admin API', link: '/deploy/admin-api' },
        ]
      },
      {
        text: 'Mesh',
        items: [
          { text: 'AIMP integration', link: '/mesh/integration' },
        ]
      },
      {
        text: 'ADRs / Design',
        items: [
          { text: 'Overview', link: '/adr/' },
          { text: '0001 · ArcSwap config hot-reload', link: '/adr/0001-arcswap-config-hot-reload' },
          { text: '0002 · Aho-Corasick over regex', link: '/adr/0002-aho-corasick-over-regex' },
          { text: '0003 · Two-level cache + generation', link: '/adr/0003-two-level-cache-with-generation' },
          { text: '0004 · HMAC-chained audit log', link: '/adr/0004-hmac-chained-audit-log' },
          { text: '0005 · Distroless + cosign/SLSA', link: '/adr/0005-distroless-with-cosign-slsa' },
          { text: '0006 · tracing + optional OTLP', link: '/adr/0006-tracing-with-optional-otlp' },
          { text: '0007 · Two-tier MSRV', link: '/adr/0007-bicapa-msrv' },
          { text: '0008 · Mesh AIMP integration', link: '/adr/0008-mesh-aimp-integration' },
          { text: '0010 · Host-based L7 routing', link: '/adr/0010-host-based-l7-routing' },
          { text: '0011 · zion import (nginx)', link: '/adr/0011-zion-import-nginx' },
          { text: '0012 · zion import (traefik)', link: '/adr/0012-zion-import-traefik' },
          { text: '0013 · zion import (caddy)', link: '/adr/0013-zion-import-caddy' },
          { text: '0014 · Importer TLS/ACME emission', link: '/adr/0014-importer-tls-acme-emission' },
          { text: '0015 · Route mode: static', link: '/adr/0015-route-mode-static' },
          { text: '0016 · Importer nginx static mapping', link: '/adr/0016-importer-nginx-static-mapping' },
          { text: '0017 · Audit-log rotation', link: '/adr/0017-audit-log-rotation' },
          { text: '0018 · Cache origin revalidation', link: '/adr/0018-cache-origin-revalidation' },
          { text: '0019 · Static conditional GET', link: '/adr/0019-static-conditional-get' },
          { text: '0020 · Static range requests', link: '/adr/0020-static-range-requests' },
          { text: '0021 · Static file streaming', link: '/adr/0021-static-file-streaming' },
          { text: '0022 · Static precompressed sidecars', link: '/adr/0022-static-precompressed-sidecars' },
          { text: '0023 · ML-WAF training pipeline', link: '/adr/0023-ml-waf-training-pipeline' },
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/zion' }
    ],

    footer: {
      message:
        'Released under the MIT License. · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
      copyright: 'Built with Rust. Benchmarked with science.',
    },

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/fabriziosalmi/zion/edit/master/docs/:path',
      text: 'Edit this page on GitHub',
    },
  }
})
