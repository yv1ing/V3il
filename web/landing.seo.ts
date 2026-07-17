export const landingSeo = {
  siteUrl: "https://v3il.fans/",
  siteName: "V3il",
  title: "V3il — Deception-Led Autonomous Blue-Team Operations",
  description:
    "V3il connects programmable deception environments, behavior and Zeek detection, ThreatIncident correlation, multi-Agent investigation, adaptive engagement, evidence, risk decisions, and intelligence reporting.",
  imagePath: "assets/v3il-logo.png",
  imageAlt: "V3il logo",
  keywords: [
    "V3il",
    "blue team operations",
    "deception platform",
    "adaptive deception",
    "autonomous investigation",
    "multi-agent security operations",
    "threat investigation",
    "attacker behavior analysis",
    "incident correlation",
    "Zeek detection",
    "threat intelligence",
    "attacker profiling",
    "evidence-led investigation",
    "security operations workbench",
  ],
};

export const structuredData = [
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: landingSeo.siteName,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Linux, Docker",
    url: landingSeo.siteUrl,
    image: new URL(landingSeo.imagePath, landingSeo.siteUrl).toString(),
    description: landingSeo.description,
    softwareRequirements: "Docker Engine, Docker Compose, PostgreSQL, and model provider credentials",
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
    },
    sameAs: ["https://github.com/yv1ing/V3il"],
  },
  {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: [
      {
        "@type": "Question",
        name: "What is V3il?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "V3il is an open-source blue-team operations platform that uses controlled deception environments to observe attacker behavior and coordinate investigation, adaptive engagement, threat intelligence, and reporting.",
        },
      },
      {
        "@type": "Question",
        name: "How does a V3il investigation work?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "V3il captures behavior and detection signals from deception environments, correlates related activity into a ThreatIncident, assigns scoped work to five specialist Agent roles, and keeps evidence, analysis, environment changes, risk, and reporting in the same case record.",
        },
      },
      {
        "@type": "Question",
        name: "Who is V3il designed for?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "V3il is designed for internal blue teams, threat research groups, and controlled security labs operating with explicit authorization, isolated infrastructure, and a trusted management network.",
        },
      },
    ],
  },
  {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      {
        "@type": "ListItem",
        position: 1,
        name: "V3il",
        item: landingSeo.siteUrl,
      },
    ],
  },
];

export function getRobotsTxt() {
  return [
    "User-agent: *",
    "Allow: /",
    "",
    "Sitemap: " + new URL("sitemap.xml", landingSeo.siteUrl).toString(),
    "",
  ].join("\n");
}

export function getSitemapXml() {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    "  <url>",
    "    <loc>" + landingSeo.siteUrl + "</loc>",
    "    <changefreq>weekly</changefreq>",
    "    <priority>1.0</priority>",
    "  </url>",
    "</urlset>",
    "",
  ].join("\n");
}

export function getWebManifest(iconSrc: string) {
  return JSON.stringify(
    {
      name: "V3il",
      short_name: "V3il",
      description: landingSeo.description,
      start_url: "/",
      display: "standalone",
      background_color: "#0a0b0d",
      theme_color: "#486f96",
      icons: [
        {
          src: iconSrc,
          sizes: "1000x1000",
          type: "image/png",
          purpose: "any",
        },
      ],
    },
    null,
    2,
  );
}
