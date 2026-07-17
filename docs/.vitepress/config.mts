import { defineConfig } from 'vitepress'

const base = '/V3il/'

const enNav = [
  { text: 'Home', link: '/en/' },
  { text: 'Architecture', link: '/en/guide/overview' },
  { text: 'Domain Models', link: '/en/guide/domain-models' },
  { text: 'Workflow', link: '/en/guide/workflow' },
  { text: 'Quick Start', link: '/en/guide/quick-start' }
]

const zhNav = [
  { text: '首页', link: '/zh/' },
  { text: '产品架构', link: '/zh/guide/overview' },
  { text: '领域模型', link: '/zh/guide/domain-models' },
  { text: '工作流程', link: '/zh/guide/workflow' },
  { text: '快速开始', link: '/zh/guide/quick-start' }
]

const enSidebar = {
  '/en/guide/': [
    {
      text: 'Guide',
      items: [
        { text: 'Product Architecture', link: '/en/guide/overview' },
        { text: 'Core Domain Models', link: '/en/guide/domain-models' },
        { text: 'End-to-End Workflow', link: '/en/guide/workflow' },
        { text: 'Deception Environments', link: '/en/guide/deception' },
        { text: 'Investigation And Evidence', link: '/en/guide/investigation' },
        { text: 'Quick Start', link: '/en/guide/quick-start' },
        { text: 'First Use', link: '/en/guide/first-use' }
      ]
    }
  ]
}

const zhSidebar = {
  '/zh/guide/': [
    {
      text: '说明文档',
      items: [
        { text: '产品架构', link: '/zh/guide/overview' },
        { text: '核心领域模型', link: '/zh/guide/domain-models' },
        { text: '端到端流程', link: '/zh/guide/workflow' },
        { text: '欺骗环境', link: '/zh/guide/deception' },
        { text: '调查与证据', link: '/zh/guide/investigation' },
        { text: '快速开始', link: '/zh/guide/quick-start' },
        { text: '首次使用', link: '/zh/guide/first-use' }
      ]
    }
  ]
}

export default defineConfig({
  base,
  title: 'V3il Documentation',
  description: 'Product architecture and operating guides for the V3il deception-led blue-team platform.',
  appearance: 'force-dark',
  lastUpdated: false,
  markdown: {
    config(md) {
      const fence = md.renderer.rules.fence
      md.renderer.rules.fence = (tokens, idx, options, env, self) => {
        const token = tokens[idx]
        const lang = token.info.trim().split(/\s+/)[0]
        if (lang === 'mermaid') {
          return `<MermaidDiagram code="${encodeURIComponent(token.content)}" />`
        }
        return fence ? fence(tokens, idx, options, env, self) : self.renderToken(tokens, idx, options)
      }
    }
  },
  themeConfig: {
    logo: '/v3il-logo.png',
    outline: { level: [2, 3], label: 'On this page' },
    socialLinks: [{ icon: 'github', link: 'https://github.com/yv1ing/V3il' }]
  },
  locales: {
    en: {
      label: 'English',
      lang: 'en-US',
      link: '/en/',
      themeConfig: {
        nav: enNav,
        sidebar: enSidebar,
        outline: { level: [2, 3], label: 'Contents' }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      link: '/zh/',
      themeConfig: {
        nav: zhNav,
        sidebar: zhSidebar,
        outline: { level: [2, 3], label: '目录' }
      }
    }
  }
})
