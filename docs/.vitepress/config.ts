import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Zion Edge Gateway',
  description: 'High-performance TLS reverse proxy with built-in WAF',
  base: '/zion/',
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/zion/logo.svg' }]],

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/' },
      { text: 'Config', link: '/config/' },
      { text: 'Benchmarks', link: '/benchmarks/' },
      { text: 'Security', link: '/security/' },
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is Zion?', link: '/guide/' },
          { text: 'Quick Start', link: '/guide/quickstart' },
          { text: 'Architecture Core', link: '/guide/architecture' },
          { text: 'Historical Lore', link: '/guide/architecture_lore' },
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
        text: 'Security',
        items: [
          { text: 'WAF Pipeline', link: '/security/' },
          { text: 'Hardening', link: '/security/hardening' },
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
      { icon: 'github', link: 'https://gitlab.edge99.net/fab/zion' }
    ],

    footer: {
      message: 'Built with Rust. Benchmarked with science.',
    }
  }
})
