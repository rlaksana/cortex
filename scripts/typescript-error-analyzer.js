#!/usr/bin/env node

/**
 * TypeScript Error Analyzer
 *
 * Advanced error categorization and trend analysis system
 * Integrates with monitoring/SLO infrastructure
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class TypeScriptErrorAnalyzer {
  constructor(options = {}) {
    this.options = {
      configPath: options.configPath || 'config/typescript-error-budget.json',
      dataDir: options.dataDir || 'artifacts/typescript-analysis',
      trendsFile: options.trendsFile || 'artifacts/typescript-analysis/trends.json',
      patternsFile: options.patternsFile || 'artifacts/typescript-analysis/error-patterns.json',
      ...options
    };

    this.config = null;
    this.errorPatterns = new Map();
    this.trendData = null;
  }

  /**
   * Execute comprehensive error analysis
   */
  async execute() {
    console.log('🔍 TypeScript Error Analyzer - Starting comprehensive analysis');

    try {
      this.loadConfiguration();
      this.ensureDirectories();
      this.loadErrorPatterns();
      this.loadTrendData();

      // Collect current error data
      const currentData = await this.collectErrorData();

      // Categorize errors
      const categorizedErrors = this.categorizeErrors(currentData.errors);

      // Analyze patterns
      const patternAnalysis = this.analyzeErrorPatterns(categorizedErrors);

      // Update trend analysis
      const trendAnalysis = this.updateTrendAnalysis(currentData, categorizedErrors);

      // Generate predictions
      const predictions = this.generatePredictions(trendAnalysis);

      // Create comprehensive report
      const report = this.generateComprehensiveReport({
        current: currentData,
        categorized: categorizedErrors,
        patterns: patternAnalysis,
        trends: trendAnalysis,
        predictions: predictions,
        timestamp: new Date().toISOString()
      });

      // Save analysis results
      this.saveAnalysis(report);

      // Generate alerts if needed
      this.generateAlerts(report);

      console.log('✅ TypeScript error analysis completed successfully');
      return report;

    } catch (error) {
      console.error('❌ TypeScript error analysis failed:', error.message);
      throw error;
    }
  }

  /**
   * Load configuration
   */
  loadConfiguration() {
    try {
      if (fs.existsSync(this.options.configPath)) {
        this.config = JSON.parse(fs.readFileSync(this.options.configPath, 'utf8'));
        console.log('✅ Configuration loaded');
      } else {
        console.warn('⚠️ Configuration not found, using defaults');
        this.config = this.getDefaultConfiguration();
      }
    } catch (error) {
      console.warn('⚠️ Failed to load configuration:', error.message);
      this.config = this.getDefaultConfiguration();
    }
  }

  /**
   * Get default configuration
   */
  getDefaultConfiguration() {
    return {
      errorBudget: {
        critical: { maxErrorCount: 0, maxErrorIncrease: 0 },
        high: { maxErrorCount: 5, maxErrorIncrease: 2 },
        medium: { maxErrorCount: 20, maxErrorIncrease: 5 },
        low: { maxErrorCount: 50, maxErrorIncrease: 10 }
      },
      analysis: {
        trendWindow: 30,
        patternWindow: 7,
        predictionWindow: 14,
        anomalyThreshold: 2.0
      },
      monitoring: {
        enableTrendAnalysis: true,
        enablePatternDetection: true,
        enablePrediction: true,
        enableAnomalyDetection: true
      }
    };
  }

  /**
   * Ensure directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.options.dataDir,
      path.join(this.options.dataDir, 'patterns'),
      path.join(this.options.dataDir, 'trends'),
      path.join(this.options.dataDir, 'reports'),
      path.join(this.options.dataDir, 'alerts')
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load error patterns from configuration and history
   */
  loadErrorPatterns() {
    // Load from configuration
    if (this.config?.errorCodeMapping) {
      for (const [code, info] of Object.entries(this.config.errorCodeMapping)) {
        this.errorPatterns.set(code, {
          category: info.category || 'unknown',
          description: info.description || '',
          commonCauses: info.commonCauses || [],
          automatedFixAvailable: info.automatedFixAvailable || false,
          fixStrategies: info.fixStrategies || [],
          historicalFrequency: 0,
          recentTrend: 'stable'
        });
      }
    }

    // Load historical patterns
    if (fs.existsSync(this.options.patternsFile)) {
      try {
        const historicalPatterns = JSON.parse(fs.readFileSync(this.options.patternsFile, 'utf8'));
        for (const [code, pattern] of Object.entries(historicalPatterns)) {
          if (this.errorPatterns.has(code)) {
            const existing = this.errorPatterns.get(code);
            this.errorPatterns.set(code, { ...existing, ...pattern });
          } else {
            this.errorPatterns.set(code, pattern);
          }
        }
        console.log('✅ Historical error patterns loaded');
      } catch (error) {
        console.warn('⚠️ Failed to load historical patterns:', error.message);
      }
    }
  }

  /**
   * Load trend data
   */
  loadTrendData() {
    if (fs.existsSync(this.options.trendsFile)) {
      try {
        this.trendData = JSON.parse(fs.readFileSync(this.options.trendsFile, 'utf8'));
        console.log('✅ Trend data loaded');
      } catch (error) {
        console.warn('⚠️ Failed to load trend data:', error.message);
        this.trendData = { daily: [], weekly: [], patterns: {} };
      }
    } else {
      this.trendData = { daily: [], weekly: [], patterns: {} };
    }
  }

  /**
   * Collect current error data
   */
  async collectErrorData() {
    console.log('📊 Collecting current TypeScript error data...');

    const startTime = Date.now();

    try {
      // Run TypeScript compiler
      const output = execSync('npx tsc --noEmit --pretty false', {
        encoding: 'utf8',
        stdio: 'pipe'
      });

      const endTime = Date.now();
      const buildTime = endTime - startTime;

      // Parse errors
      const errors = this.parseTypeScriptOutput(output);

      // Calculate metrics
      const metrics = this.calculateMetrics(errors, buildTime);

      return {
        timestamp: new Date().toISOString(),
        errors,
        metrics,
        buildTime,
        compilationSuccess: false
      };

    } catch (error) {
      // TypeScript compilation failed
      const output = error.stderr || error.stdout || '';
      const errors = this.parseTypeScriptOutput(output);
      const endTime = Date.now();
      const buildTime = endTime - startTime;

      return {
        timestamp: new Date().toISOString(),
        errors,
        metrics: this.calculateMetrics(errors, buildTime),
        buildTime,
        compilationSuccess: false
      };
    }
  }

  /**
   * Parse TypeScript compiler output
   */
  parseTypeScriptOutput(output) {
    const errors = [];
    const lines = output.split('\n');

    for (const line of lines) {
      // Parse error format: file(line,column): error TS####: message
      const match = line.match(/^(.+?)\((\d+),(\d+)\):\s+error\s+(TS\d+):\s+(.+)$/);
      if (match) {
        errors.push({
          file: match[1].trim(),
          line: parseInt(match[2]),
          column: parseInt(match[3]),
          code: match[4].replace('TS', ''),
          message: match[5].trim(),
          category: this.getInitialCategory(match[4].replace('TS', ''))
        });
      }
    }

    return errors;
  }

  /**
   * Calculate error metrics
   */
  calculateMetrics(errors, buildTime) {
    const metrics = {
      totalErrors: errors.length,
      errorsByCategory: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      errorsByCode: {},
      errorsByFile: {},
      topErrorFiles: [],
      topErrorCodes: []
    };

    for (const error of errors) {
      // Count by category
      if (metrics.errorsByCategory[error.category] !== undefined) {
        metrics.errorsByCategory[error.category]++;
      } else {
        metrics.errorsByCategory.unknown++;
      }

      // Count by code
      metrics.errorsByCode[error.code] = (metrics.errorsByCode[error.code] || 0) + 1;

      // Count by file
      const relativeFile = path.relative(process.cwd(), error.file);
      metrics.errorsByFile[relativeFile] = (metrics.errorsByFile[relativeFile] || 0) + 1;
    }

    // Get top files and codes
    metrics.topErrorFiles = Object.entries(metrics.errorsByFile)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([file, count]) => ({ file, count }));

    metrics.topErrorCodes = Object.entries(metrics.errorsByCode)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([code, count]) => ({ code, count }));

    return metrics;
  }

  /**
   * Get initial category for error code
   */
  getInitialCategory(errorCode) {
    const pattern = this.errorPatterns.get(errorCode);
    return pattern?.category || 'unknown';
  }

  /**
   * Categorize errors with enhanced analysis
   */
  categorizeErrors(errors) {
    console.log('🏷️ Categorizing errors...');

    const categorized = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: []
    };

    for (const error of errors) {
      const pattern = this.errorPatterns.get(error.code);
      let category = error.category;

      // Enhanced categorization based on context
      if (pattern) {
        category = this.enhanceCategorization(error, pattern);
      }

      // Add enhanced information
      error.enhancedCategory = category;
      error.patternInfo = pattern || null;
      error.context = this.analyzeContext(error);

      categorized[category] = (categorized[category] || []).push(error);
    }

    return categorized;
  }

  /**
   * Enhance categorization based on context
   */
  enhanceCategorization(error, pattern) {
    let category = pattern.category;

    // Upgrade severity based on file location
    if (error.file.includes('test') && category === 'high') {
      category = 'medium'; // Test errors are less critical
    }

    // Upgrade severity based on error frequency
    const historicalFreq = pattern.historicalFrequency || 0;
    if (historicalFreq > 10 && category === 'medium') {
      category = 'high'; // Frequent medium errors become high priority
    }

    // Upgrade based on impact
    if (error.message.includes('Cannot find module') && category !== 'critical') {
      category = 'critical'; // Module resolution issues are critical
    }

    return category;
  }

  /**
   * Analyze error context
   */
  analyzeContext(error) {
    const context = {
      fileExtension: path.extname(error.file),
      directory: path.dirname(error.file),
      isTestFile: error.file.includes('test') || error.file.includes('spec'),
      isTypeFile: error.file.endsWith('.d.ts'),
      isInNodeModules: error.file.includes('node_modules'),
      isInSource: !error.file.includes('node_modules') && !error.file.includes('.git')
    };

    // Analyze file structure complexity
    try {
      const fileContent = fs.readFileSync(error.file, 'utf8');
      context.fileSize = fileContent.length;
      context.lineCount = fileContent.split('\n').length;
      context.hasComplexTypes = fileContent.includes('interface') || fileContent.includes('type');
      context.hasGenerics = fileContent.includes('<') && fileContent.includes('>');
    } catch (err) {
      context.fileAccessible = false;
    }

    return context;
  }

  /**
   * Analyze error patterns
   */
  analyzeErrorPatterns(categorizedErrors) {
    console.log('🔍 Analyzing error patterns...');

    const analysis = {
      patterns: {},
      correlations: [],
      recommendations: [],
      insights: []
    };

    // Analyze each category
    for (const [category, errors] of Object.entries(categorizedErrors)) {
      if (errors.length === 0) continue;

      analysis.patterns[category] = this.analyzeCategoryPatterns(errors);
    }

    // Find correlations
    analysis.correlations = this.findErrorCorrelations(categorizedErrors);

    // Generate recommendations
    analysis.recommendations = this.generatePatternRecommendations(analysis.patterns, analysis.correlations);

    // Generate insights
    analysis.insights = this.generateInsights(analysis.patterns, categorizedErrors);

    return analysis;
  }

  /**
   * Analyze patterns within a category
   */
  analyzeCategoryPatterns(errors) {
    const patterns = {
      totalErrors: errors.length,
      topErrorCodes: {},
      topFiles: {},
      commonCauses: {},
      fixPotential: 0,
      automationScore: 0
    };

    // Analyze error codes
    for (const error of errors) {
      patterns.topErrorCodes[error.code] = (patterns.topErrorCodes[error.code] || 0) + 1;

      if (error.patternInfo?.automatedFixAvailable) {
        patterns.fixPotential++;
        patterns.automationScore++;
      }

      // Track common causes
      if (error.patternInfo?.commonCauses) {
        for (const cause of error.patternInfo.commonCauses) {
          patterns.commonCauses[cause] = (patterns.commonCauses[cause] || 0) + 1;
        }
      }
    }

    // Analyze files
    for (const error of errors) {
      const file = error.context?.isInSource ? error.file : 'external';
      patterns.topFiles[file] = (patterns.topFiles[file] || 0) + 1;
    }

    // Calculate automation score
    patterns.automationScore = patterns.totalErrors > 0 ?
      (patterns.automationScore / patterns.totalErrors) * 100 : 0;

    return patterns;
  }

  /**
   * Find correlations between errors
   */
  findErrorCorrelations(categorizedErrors) {
    const correlations = [];

    // File-based correlations
    const fileErrors = new Map();
    for (const errors of Object.values(categorizedErrors)) {
      for (const error of errors) {
        if (!fileErrors.has(error.file)) {
          fileErrors.set(error.file, []);
        }
        fileErrors.get(error.file).push(error);
      }
    }

    // Find files with multiple error types
    for (const [file, errors] of fileErrors.entries()) {
      if (errors.length > 3) {
        const errorCodes = [...new Set(errors.map(e => e.code))];
        if (errorCodes.length > 1) {
          correlations.push({
            type: 'file_concentration',
            file,
            errorCount: errors.length,
            errorCodes,
            recommendation: 'Review file architecture and type definitions'
          });
        }
      }
    }

    // Time-based correlations (if trend data available)
    if (this.trendData.daily.length > 0) {
      const recentData = this.trendData.daily.slice(-7);
      const avgErrors = recentData.reduce((sum, day) => sum + day.totalErrors, 0) / recentData.length;
      const currentTotal = Object.values(categorizedErrors).reduce((sum, errors) => sum + errors.length, 0);

      if (currentTotal > avgErrors * 1.5) {
        correlations.push({
          type: 'spike_detected',
          currentErrors: currentTotal,
          historicalAverage: avgErrors,
          spikeRatio: (currentTotal / avgErrors).toFixed(2),
          recommendation: 'Investigate recent changes that may have introduced errors'
        });
      }
    }

    return correlations;
  }

  /**
   * Generate pattern-based recommendations
   */
  generatePatternRecommendations(patterns, correlations) {
    const recommendations = [];

    // Category-specific recommendations
    for (const [category, pattern] of Object.entries(patterns)) {
      if (pattern.totalErrors === 0) continue;

      // High automation potential
      if (pattern.automationScore > 50) {
        recommendations.push({
          priority: 'high',
          category,
          type: 'automation',
          message: `${category} errors have high automation potential (${pattern.automationScore.toFixed(1)}%)`,
          action: 'Run targeted ts-fix scripts for this category',
          impact: 'high'
        });
      }

      // File concentration
      if (Object.keys(pattern.topFiles).length > 0) {
        const topFile = Object.entries(pattern.topFiles)
          .sort(([,a], [,b]) => b - a)[0];

        if (topFile[1] > 5) {
          recommendations.push({
            priority: 'medium',
            category,
            type: 'file_focus',
            message: `High error concentration in ${topFile[0]} (${topFile[1]} errors)`,
            action: `Review and refactor ${topFile[0]} type definitions`,
            impact: 'medium'
          });
        }
      }
    }

    // Correlation-based recommendations
    for (const correlation of correlations) {
      recommendations.push({
        priority: correlation.type === 'spike_detected' ? 'high' : 'medium',
        type: correlation.type,
        message: correlation.recommendation,
        action: correlation.recommendation,
        impact: 'medium'
      });
    }

    return recommendations;
  }

  /**
   * Generate insights from analysis
   */
  generateInsights(patterns, categorizedErrors) {
    const insights = [];

    // Error distribution insights
    const totalErrors = Object.values(categorizedErrors).reduce((sum, errors) => sum + errors.length, 0);
    const criticalErrors = categorizedErrors.critical?.length || 0;

    if (criticalErrors > 0) {
      insights.push({
        type: 'critical_risk',
        message: `${criticalErrors} critical errors detected - immediate attention required`,
        impact: 'Critical errors may affect runtime behavior',
        timeframe: 'immediate'
      });
    }

    // Pattern insights
    for (const [category, pattern] of Object.entries(patterns)) {
      if (pattern.totalErrors > 10) {
        insights.push({
          type: 'pattern_concentration',
          message: `${category} errors constitute significant portion (${((pattern.totalErrors/totalErrors)*100).toFixed(1)}%)`,
          impact: 'Focus automation efforts on this category',
          timeframe: 'short-term'
        });
      }
    }

    return insights;
  }

  /**
   * Update trend analysis
   */
  updateTrendAnalysis(currentData, categorizedErrors) {
    console.log('📈 Updating trend analysis...');

    const trendPoint = {
      timestamp: currentData.timestamp,
      totalErrors: currentData.metrics.totalErrors,
      categories: {},
      buildTime: currentData.buildTime,
      compilationSuccess: currentData.compilationSuccess
    };

    // Add category breakdown
    for (const [category, errors] of Object.entries(categorizedErrors)) {
      trendPoint.categories[category] = errors.length;
    }

    // Update trend data
    this.trendData.daily.push(trendPoint);

    // Keep only last 30 days
    if (this.trendData.daily.length > 30) {
      this.trendData.daily = this.trendData.daily.slice(-30);
    }

    // Calculate trend analysis
    const analysis = this.calculateTrendMetrics();

    return analysis;
  }

  /**
   * Calculate trend metrics
   */
  calculateTrendMetrics() {
    if (this.trendData.daily.length < 2) {
      return { trend: 'insufficient_data' };
    }

    const recent = this.trendData.daily.slice(-7);
    const previous = this.trendData.daily.slice(-14, -7);

    const recentAvg = recent.reduce((sum, day) => sum + day.totalErrors, 0) / recent.length;
    const previousAvg = previous.length > 0 ?
      previous.reduce((sum, day) => sum + day.totalErrors, 0) / previous.length : recentAvg;

    const trendDirection = recentAvg > previousAvg * 1.1 ? 'increasing' :
                          recentAvg < previousAvg * 0.9 ? 'decreasing' : 'stable';

    const trendPercent = previousAvg > 0 ? ((recentAvg - previousAvg) / previousAvg * 100) : 0;

    // Calculate trend by category
    const categoryTrends = {};
    const categories = ['critical', 'high', 'medium', 'low'];

    for (const category of categories) {
      const recentCategoryAvg = recent.reduce((sum, day) =>
        sum + (day.categories[category] || 0), 0) / recent.length;
      const previousCategoryAvg = previous.length > 0 ?
        previous.reduce((sum, day) => sum + (day.categories[category] || 0), 0) / previous.length : recentCategoryAvg;

      categoryTrends[category] = {
        trend: recentCategoryAvg > previousCategoryAvg * 1.1 ? 'increasing' :
               recentCategoryAvg < previousCategoryAvg * 0.9 ? 'decreasing' : 'stable',
        current: recentCategoryAvg,
        previous: previousCategoryAvg,
        percentChange: previousCategoryAvg > 0 ?
          ((recentCategoryAvg - previousCategoryAvg) / previousCategoryAvg * 100) : 0
      };
    }

    return {
      trend: trendDirection,
      percentChange: trendPercent,
      recentAverage: recentAvg,
      previousAverage: previousAvg,
      categoryTrends,
      dataPoints: this.trendData.daily.length
    };
  }

  /**
   * Generate predictions based on trends
   */
  generatePredictions(trendAnalysis) {
    console.log('🔮 Generating predictions...');

    const predictions = [];

    if (trendAnalysis.trend === 'insufficient_data') {
      predictions.push({
        type: 'data_insufficient',
        confidence: 'low',
        message: 'Insufficient historical data for reliable predictions',
        timeframe: '2+ weeks'
      });
      return predictions;
    }

    // Error count predictions
    if (trendAnalysis.trend === 'increasing') {
      predictions.push({
        type: 'error_increase',
        confidence: 'medium',
        message: `Error count trending upward by ${Math.abs(trendAnalysis.percentChange).toFixed(1)}%`,
        impact: 'May exceed error budget in 1-2 weeks if trend continues',
        timeframe: '1-2 weeks',
        recommendedAction: 'Increase type safety measures and code review focus'
      });
    }

    // Category-specific predictions
    for (const [category, catTrend] of Object.entries(trendAnalysis.categoryTrends)) {
      if (catTrend.trend === 'increasing' && catTrend.current > 0) {
        predictions.push({
          type: 'category_increase',
          category,
          confidence: 'medium',
          message: `${category} errors increasing by ${Math.abs(catTrend.percentChange).toFixed(1)}%`,
          impact: category === 'critical' ? 'High risk to production stability' : 'Development friction',
          timeframe: '1 week',
          recommendedAction: `Focus ${category} error reduction efforts immediately`
        });
      }
    }

    return predictions;
  }

  /**
   * Generate comprehensive report
   */
  generateComprehensiveReport(data) {
    console.log('📋 Generating comprehensive report...');

    const report = {
      metadata: {
        timestamp: data.timestamp,
        analyzerVersion: '1.0.0',
        dataPoints: this.trendData.daily.length
      },
      summary: {
        totalErrors: data.current.metrics.totalErrors,
        criticalErrors: data.categorized.critical?.length || 0,
        buildTime: data.current.buildTime,
        overallTrend: data.trends.trend,
        riskLevel: this.calculateRiskLevel(data),
        automationPotential: this.calculateAutomationPotential(data)
      },
      current: {
        timestamp: data.current.timestamp,
        metrics: data.current.metrics,
        categorized: Object.fromEntries(
          Object.entries(data.categorized).map(([k, v]) => [k, v.length])
        )
      },
      patterns: data.patterns,
      trends: data.trends,
      predictions: data.predictions,
      recommendations: this.prioritizeRecommendations(data.patterns.recommendations),
      insights: data.patterns.insights
    };

    return report;
  }

  /**
   * Calculate overall risk level
   */
  calculateRiskLevel(data) {
    const criticalErrors = data.categorized.critical?.length || 0;
    const totalErrors = data.current.metrics.totalErrors;
    const trendDirection = data.trends.trend;

    let riskScore = 0;

    // Critical errors carry highest weight
    riskScore += criticalErrors * 10;

    // High errors
    riskScore += (data.categorized.high?.length || 0) * 5;

    // Trend direction
    if (trendDirection === 'increasing') {
      riskScore += 20;
    }

    // Total error volume
    if (totalErrors > 20) {
      riskScore += 10;
    } else if (totalErrors > 10) {
      riskScore += 5;
    }

    if (riskScore >= 50) return 'critical';
    if (riskScore >= 30) return 'high';
    if (riskScore >= 15) return 'medium';
    return 'low';
  }

  /**
   * Calculate automation potential
   */
  calculateAutomationPotential(data) {
    let automationScore = 0;
    let totalErrors = data.current.metrics.totalErrors;

    for (const [category, pattern] of Object.entries(data.patterns.patterns)) {
      automationScore += pattern.fixPotential || 0;
    }

    return totalErrors > 0 ? (automationScore / totalErrors) * 100 : 0;
  }

  /**
   * Prioritize recommendations
   */
  prioritizeRecommendations(recommendations) {
    return recommendations.sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const aPriority = priorityOrder[a.priority] || 0;
      const bPriority = priorityOrder[b.priority] || 0;

      if (aPriority !== bPriority) {
        return bPriority - aPriority;
      }

      return b.impact.localeCompare(a.impact);
    });
  }

  /**
   * Save analysis results
   */
  saveAnalysis(report) {
    // Save comprehensive report
    const reportPath = path.join(this.options.dataDir, 'reports', `analysis-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    // Save updated trend data
    fs.writeFileSync(this.options.trendsFile, JSON.stringify(this.trendData, null, 2));

    // Save updated patterns
    const patternsData = Object.fromEntries(this.errorPatterns);
    fs.writeFileSync(this.options.patternsFile, JSON.stringify(patternsData, null, 2));

    console.log(`📊 Analysis saved to ${reportPath}`);
  }

  /**
   * Generate alerts if needed
   */
  generateAlerts(report) {
    const alerts = [];

    // Critical error alerts
    if (report.summary.criticalErrors > 0) {
      alerts.push({
        type: 'critical_errors',
        severity: 'critical',
        message: `${report.summary.criticalErrors} critical TypeScript errors detected`,
        action: 'Immediate attention required - may affect runtime behavior'
      });
    }

    // Trend alerts
    if (report.trends.trend === 'increasing' && Math.abs(report.trends.percentChange) > 20) {
      alerts.push({
        type: 'trend_regression',
        severity: 'high',
        message: `TypeScript errors increasing by ${Math.abs(report.trends.percentChange).toFixed(1)}%`,
        action: 'Investigate recent changes and consider code review practices'
      });
    }

    // Risk level alerts
    if (report.summary.riskLevel === 'critical') {
      alerts.push({
        type: 'high_risk',
        severity: 'critical',
        message: 'TypeScript error risk level is critical',
        action: 'Implement immediate mitigation strategies'
      });
    }

    // Save alerts
    if (alerts.length > 0) {
      const alertPath = path.join(this.options.dataDir, 'alerts', `alerts-${Date.now()}.json`);
      fs.writeFileSync(alertPath, JSON.stringify(alerts, null, 2));
      console.log(`🚨 ${alerts.length} alerts generated and saved to ${alertPath}`);

      // Display alerts
      alerts.forEach(alert => {
        console.log(`🚨 [${alert.severity.toUpperCase()}] ${alert.message}`);
        console.log(`   Action: ${alert.action}`);
      });
    }
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--config':
        options.configPath = args[++i];
        break;
      case '--data-dir':
        options.dataDir = args[++i];
        break;
      case '--verbose':
        options.verbose = true;
        break;
    }
  }

  const analyzer = new TypeScriptErrorAnalyzer(options);
  analyzer.execute()
    .then(report => {
      console.log('\n📊 Analysis Summary:');
      console.log(`  Total Errors: ${report.summary.totalErrors}`);
      console.log(`  Critical Errors: ${report.summary.criticalErrors}`);
      console.log(`  Risk Level: ${report.summary.riskLevel}`);
      console.log(`  Trend: ${report.trends.trend}`);
      console.log(`  Automation Potential: ${report.summary.automationPotential.toFixed(1)}%`);
      console.log(`  Recommendations: ${report.recommendations.length}`);

      process.exit(0);
    })
    .catch(error => {
      console.error('Analysis failed:', error.message);
      process.exit(1);
    });
}

module.exports = TypeScriptErrorAnalyzer;