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
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/zion/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0b0b0d' }],
    ['meta', { property: 'og:title', content: 'Zion Edge Gateway' }],
    ['meta', { property: 'og:description', content: 'One auditable Rust binary at the edge — TLS 1.3, a zero-regex WAF, and a two-level RAM cache. No sidecars, no control plane.' }],
    ['meta', { property: 'og:type', content: 'website' }],
  ],

  lastUpdated: true,
  cleanUrls: true,

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
    logo: '/logo.svg',
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
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/zion' }
    ],

    footer: {
      message: 'Released under the MIT License.',
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
