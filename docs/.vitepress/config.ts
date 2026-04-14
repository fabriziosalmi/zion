import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Zion Edge Gateway',
  description: 'High-performance TLS reverse proxy with built-in WAF, written in Rust',
  base: '/zion/',
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/zion/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0071e3' }],
    ['meta', { property: 'og:title', content: 'Zion Edge Gateway' }],
    ['meta', { property: 'og:description', content: 'High-performance TLS reverse proxy with built-in WAF. 235K req/s. Rust.' }],
    ['meta', { property: 'og:type', content: 'website' }],
  ],

  lastUpdated: true,
  cleanUrls: true,

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
        text: 'v0.1.3',
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
          { text: 'Architecture', link: '/guide/architecture' },
        ]
      },
      {
        text: 'Configuration',
        items: [
          { text: 'Reference', link: '/config/' },
          { text: 'TLS & SNI', link: '/config/tls' },
          { text: 'Routing', link: '/config/routing' },
          { text: 'WAF', link: '/config/waf' },
          { text: 'CORS', link: '/config/cors' },
          { text: 'Authentication', link: '/config/auth' },
          { text: 'HTTP/3 (QUIC)', link: '/config/http3' },
        ]
      },
      {
        text: 'Security',
        items: [
          { text: 'WAF Pipeline', link: '/security/' },
          { text: 'Hardening', link: '/security/hardening' },
        ]
      },
      {
        text: 'Performance',
        items: [
          { text: 'Benchmarks', link: '/benchmarks/' },
          { text: 'Optimization Log', link: '/benchmarks/optimization' },
        ]
      },
      {
        text: 'Operations',
        items: [
          { text: 'Deployment', link: '/deploy/' },
          { text: 'Observability', link: '/deploy/observability' },
        ]
      }
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
