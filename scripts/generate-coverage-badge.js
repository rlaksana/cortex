#!/usr/bin/env node

/**
 * Generate Coverage Badge
 * Creates a coverage badge for display in README and GitHub
 */

import fs from 'fs/promises';
import path from 'path';

class CoverageBadgeGenerator {
  constructor() {
    this.projectRoot = process.cwd();
    this.coverageDir = path.join(this.projectRoot, 'coverage');
    this.badgesDir = path.join(this.coverageDir, 'badges');
  }

  async init() {
    console.log('🏷️  Generating coverage badge...');
    await this.ensureDirectories();
    await this.generateBadge();
    console.log('✅ Coverage badge generated successfully!');
  }

  async ensureDirectories() {
    await fs.mkdir(this.badgesDir, { recursive: true });
  }

  async generateBadge() {
    try {
      const coverageFile = path.join(this.coverageDir, 'coverage-summary.json');
      const coverageData = JSON.parse(await fs.readFile(coverageFile, 'utf8'));

      const total = coverageData.total;
      const overallCoverage = Math.round(
        (total.lines.pct + total.functions.pct + total.statements.pct) / 3
      );

      const badge = {
        schemaVersion: 1,
        label: 'coverage',
        message: `${overallCoverage}%`,
        color: this.getBadgeColor(overallCoverage),
      };

      const badgeSvg = this.generateBadgeSvg(badge);

      // Save the badge
      await fs.writeFile(path.join(this.badgesDir, 'coverage-badge.svg'), badgeSvg);

      // Also save as latest
      await fs.writeFile(path.join(this.badgesDir, 'coverage-latest.svg'), badgeSvg);

      // Save JSON version
      await fs.writeFile(
        path.join(this.badgesDir, 'coverage-badge.json'),
        JSON.stringify(badge, null, 2)
      );

      console.log(`📊 Overall Coverage: ${overallCoverage}%`);
      console.log(`🎨 Badge Color: ${badge.color}`);
    } catch (error) {
      console.warn('⚠️  Could not generate badge:', error.message);

      // Generate a default "unknown" badge
      const defaultBadge = {
        schemaVersion: 1,
        label: 'coverage',
        message: 'unknown',
        color: 'lightgrey',
      };

      const defaultSvg = this.generateBadgeSvg(defaultBadge);
      await fs.writeFile(path.join(this.badgesDir, 'coverage-badge.svg'), defaultSvg);
    }
  }

  getBadgeColor(coverage) {
    if (coverage >= 95) return 'brightgreen';
    if (coverage >= 90) return 'green';
    if (coverage >= 80) return 'yellowgreen';
    if (coverage >= 70) return 'yellow';
    if (coverage >= 60) return 'orange';
    return 'red';
  }

  generateBadgeSvg(badge) {
    const colors = {
      brightgreen: '#4c1',
      green: '#97ca00',
      yellowgreen: '#a4a61d',
      yellow: '#dfb317',
      orange: '#fe7d37',
      red: '#e05d44',
      lightgrey: '#9f9f9f',
    };

    const color = colors[badge.color] || '#9f9f9f';
    const messageWidth = badge.message.length * 11 + 20;
    const totalWidth = 90 + messageWidth;

    return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
  <linearGradient id="a" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="${totalWidth}" height="20" fill="#555"/>
  <rect rx="3" x="37" width="${messageWidth}" height="20" fill="${color}"/>
  <path fill="${color}" d="M37 0h4v20h-4z"/>
  <rect rx="3" width="${totalWidth}" height="20" fill="url(#a)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="18.5" y="15" fill="#010101" fill-opacity=".3">${badge.label}</text>
    <text x="18.5" y="14">${badge.label}</text>
    <text x="${37 + messageWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${badge.message}</text>
    <text x="${37 + messageWidth / 2}" y="14">${badge.message}</text>
  </g>
</svg>`;
  }
}

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const generator = new CoverageBadgeGenerator();
  generator.init().catch(console.error);
}

export default CoverageBadgeGenerator;
