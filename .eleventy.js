import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
// import { eleventyImageTransformPlugin } from "@11ty/eleventy-img";

const require = createRequire(import.meta.url);

export default function(eleventyConfig) {
  eleventyConfig.addPassthroughCopy({ "src/images": "images" });
  eleventyConfig.addPassthroughCopy({ "src/_assets/css": "css" });
  eleventyConfig.addPassthroughCopy({ "src/_assets/js": "js" });
  // eleventyConfig.addPassthroughCopy({ "src/_assets/fonts": "fonts" });
  // eleventyConfig.addPassthroughCopy({ "src/_assets/*.{webmanifest,txt,xml,png,jpg,jpeg,webp,svg,gif,ico}": "."});

	// // Configure Eleventy Image HTML transform to generate responsive images
  // // from the resolved source paths, and publish them under /images
	// eleventyConfig.addPlugin(eleventyImageTransformPlugin, {
  //   formats: ["avif", "webp", "jpeg"],
  //   widths: [320, 640, 960, 1280, 1920],
  //   svgShortCircuit: true,
  //   urlPath: "/images",
  //   outputDir: "./_site/images",
  // });
	// eleventyConfig.addPlugin(eleventyImageTransformPlugin);

  // Minimal Nunjucks date filter used by templates, e.g. {{ "now" | date("yyyy") }}
  // Supports:
  // - value: 'now' or any Date/string parseable by Date
  // - format: currently 'yyyy' for year; falls back to ISO string otherwise
  eleventyConfig.addNunjucksFilter('date', function(value, format = 'yyyy') {
    const toDate = (val) => {
      if (val === 'now' || val === undefined || val === null) return new Date();
      if (val instanceof Date) return val;
      const d = new Date(val);
      return isNaN(d.getTime()) ? new Date() : d;
    };
    const d = toDate(value);
    if (format === 'yyyy') {
      // Use UTC year to avoid timezone edge cases around New Year
      return String(d.getUTCFullYear());
    }
    return d.toISOString();
  });

  eleventyConfig.addGlobalData('siteUrl', () => {
    return process.env.SITE_URL || 'https://unknown.domain';
  });

  // Expose build metadata globally to templates as `build`
  // Captures build timestamp, runtime versions, platform hints, and git info (if available)
  eleventyConfig.addGlobalData('build', () => {
    const safe = (cmd) => {
      try {
        return execSync(cmd, { encoding: 'utf8' }).trim();
      } catch (_) {
        return null;
      }
    };

    // Platform detection (best-effort)
    const platform = [
      process.env.CF_PAGES ? 'Cloudflare Pages' : null,
      process.env.NETLIFY ? 'Netlify' : null,
      process.env.VERCEL ? 'Vercel' : null,
      process.env.GITHUB_ACTIONS ? 'GitHub Actions' : null,
      process.env.CI ? 'CI' : null,
    ].filter(Boolean)[0] || 'local';

    const git = {
      branch: safe('git rev-parse --abbrev-ref HEAD'),
      commit: safe('git rev-parse --short HEAD'),
      commitDate: safe('git show -s --format=%cI HEAD'),
    };

    let eleventyVersion = null;
    try {
      eleventyVersion = require('@11ty/eleventy/package.json').version;
    } catch (_) {
      eleventyVersion = null;
    }

    return {
      builtAt: new Date().toISOString(),
      nodeVersion: process.version,
      eleventyVersion,
      env: process.env.NODE_ENV || null,
      platform,
      git,
    };
  });

  return {
    dir: {
      input: "src",
      includes: "_includes",
      output: "_site"
    },
    templateFormats: ["njk", "md", "html"],
    htmlTemplateEngine: "njk",
    markdownTemplateEngine: "njk"
  };
}
