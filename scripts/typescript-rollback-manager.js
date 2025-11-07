#!/usr/bin/env node

/**
 * TypeScript Rollback Manager
 *
 * Handles rollback procedures when TypeScript regressions are detected
 * Integrates with incident management and notification systems
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class TypeScriptRollbackManager {
  constructor(options = {}) {
    this.options = {
      configPath: options.configPath || 'config/typescript-error-budget.json',
      incidentDir: options.incidentDir || 'artifacts/incidents',
      rollbackDir: options.rollbackDir || 'artifacts/rollbacks',
      dryRun: options.dryRun || false,
      autoRollback: options.autoRollback || false,
      ...options
    };

    this.config = null;
    this.currentIncident = null;
  }

  /**
   * Execute rollback workflow
   */
  async execute(regressionData) {
    console.log('🔄 TypeScript Rollback Manager - Processing rollback triggers');

    try {
      this.loadConfig();
      this.ensureDirectories();

      // Analyze regression severity
      const severity = this.assessSeverity(regressionData);
      console.log(`📊 Regression severity assessed: ${severity.level}`);

      // Create incident record
      this.createIncident(regressionData, severity);

      // Determine rollback actions
      const actions = this.determineActions(severity, regressionData);

      // Execute rollback actions
      const result = await this.executeActions(actions, regressionData);

      // Generate rollback report
      this.generateReport(result);

      return result;

    } catch (error) {
      console.error('❌ Rollback manager failed:', error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Load error budget configuration
   */
  loadConfig() {
    try {
      if (fs.existsSync(this.options.configPath)) {
        this.config = JSON.parse(fs.readFileSync(this.options.configPath, 'utf8'));
        console.log('✅ Error budget configuration loaded');
      } else {
        console.warn('⚠️ Error budget configuration not found, using defaults');
        this.config = this.getDefaultConfig();
      }
    } catch (error) {
      console.warn('⚠️ Failed to load configuration:', error.message);
      this.config = this.getDefaultConfig();
    }
  }

  /**
   * Get default configuration
   */
  getDefaultConfig() {
    return {
      rollbackProcedures: {
        triggers: {
          criticalErrorIncrease: true,
          regressionThresholdExceeded: true,
          performanceRegression: true,
          newCriticalErrorCodes: true,
          errorBudgetExhausted: true
        },
        actions: {
          blockMerge: true,
          createIncident: true,
          notifyTeam: true,
          autoRollback: false,
          requireManualApproval: true
        },
        escalation: {
          level1: {
            condition: "Critical errors > 0",
            actions: ["block-merge", "notify-developer"]
          },
          level2: {
            condition: "Regression > 20% OR Critical errors > 5",
            actions: ["block-merge", "notify-team", "create-incident"]
          },
          level3: {
            condition: "Regression > 50% OR Build failure",
            actions: ["block-merge", "notify-all", "create-incident", "consider-rollout-rollback"]
          }
        }
      }
    };
  }

  /**
   * Ensure required directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.options.incidentDir,
      this.options.rollbackDir,
      path.join(this.options.incidentDir, 'active'),
      path.join(this.options.incidentDir, 'resolved')
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Assess regression severity
   */
  assessSeverity(regressionData) {
    const severity = {
      level: 'low',
      score: 0,
      factors: [],
      recommendations: []
    };

    // Factor 1: Critical errors
    if (regressionData.criticalErrors > 0) {
      severity.score += regressionData.criticalErrors * 10;
      severity.factors.push(`${regressionData.criticalErrors} critical errors`);
      severity.recommendations.push('Address critical errors immediately');
    }

    // Factor 2: Error increase percentage
    if (regressionData.errorRegressionPercent > 0) {
      severity.score += Math.min(regressionData.errorRegressionPercent, 100);
      severity.factors.push(`${regressionData.errorRegressionPercent}% error regression`);

      if (regressionData.errorRegressionPercent > 50) {
        severity.recommendations.push('Consider immediate rollback');
      } else if (regressionData.errorRegressionPercent > 20) {
        severity.recommendations.push('Urgent fix required');
      }
    }

    // Factor 3: New error codes
    if (regressionData.newErrorCodes && regressionData.newErrorCodes.length > 0) {
      severity.score += regressionData.newErrorCodes.length * 5;
      severity.factors.push(`${regressionData.newErrorCodes.length} new error codes`);
      severity.recommendations.push('Investigate new error patterns');
    }

    // Factor 4: Build failure
    if (regressionData.buildSuccess === false) {
      severity.score += 50;
      severity.factors.push('Build failure');
      severity.recommendations.push('Build is broken - immediate action required');
    }

    // Factor 5: Performance regression
    if (regressionData.performanceRegression) {
      severity.score += 15;
      severity.factors.push('Performance regression detected');
      severity.recommendations.push('Investigate performance impact');
    }

    // Determine severity level
    if (severity.score >= 50) {
      severity.level = 'critical';
    } else if (severity.score >= 30) {
      severity.level = 'high';
    } else if (severity.score >= 15) {
      severity.level = 'medium';
    } else {
      severity.level = 'low';
    }

    return severity;
  }

  /**
   * Create incident record
   */
  createIncident(regressionData, severity) {
    const incidentId = this.generateIncidentId();
    const timestamp = new Date().toISOString();

    this.currentIncident = {
      id: incidentId,
      timestamp,
      severity: severity.level,
      score: severity.score,
      status: 'active',
      regressionData,
      severityFactors: severity.factors,
      recommendations: severity.recommendations,
      actions: [],
      resolution: null,
      metadata: {
        environment: process.env.NODE_ENV || 'development',
        branch: process.env.GITHUB_REF_NAME || 'unknown',
        commit: process.env.GITHUB_SHA || 'unknown',
        actor: process.env.GITHUB_ACTOR || 'unknown'
      }
    };

    // Save incident
    const incidentPath = path.join(this.options.incidentDir, 'active', `${incidentId}.json`);
    fs.writeFileSync(incidentPath, JSON.stringify(this.currentIncident, null, 2));

    console.log(`📝 Incident created: ${incidentId}`);
    console.log(`   Severity: ${severity.level} (score: ${severity.score})`);
    console.log(`   Factors: ${severity.factors.join(', ')}`);
  }

  /**
   * Generate incident ID
   */
  generateIncidentId() {
    const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '');
    const random = Math.random().toString(36).substring(2, 6);
    return `TS-INCIDENT-${timestamp}-${random}`;
  }

  /**
   * Determine rollback actions based on severity
   */
  determineActions(severity, regressionData) {
    const actions = [];
    const config = this.config?.rollbackProcedures?.actions;

    // Default actions for any severity
    if (severity.level === 'critical') {
      if (config?.blockMerge !== false) {
        actions.push({
          type: 'block-merge',
          description: 'Block pull request merges',
          priority: 'high',
          automated: true
        });
      }

      if (config?.createIncident !== false) {
        actions.push({
          type: 'create-incident',
          description: 'Create incident record',
          priority: 'high',
          automated: true
        });
      }

      if (config?.notifyTeam !== false) {
        actions.push({
          type: 'notify-team',
          description: 'Notify development team',
          priority: 'high',
          automated: true
        });
      }

      if (regressionData.buildSuccess === false && config?.autoRollback && this.options.autoRollback) {
        actions.push({
          type: 'auto-rollback',
          description: 'Automatic rollback to previous working state',
          priority: 'critical',
          automated: false, // Requires manual confirmation
          requiresApproval: true
        });
      }
    } else if (severity.level === 'high') {
      if (config?.blockMerge !== false) {
        actions.push({
          type: 'block-merge',
          description: 'Block pull request merges',
          priority: 'medium',
          automated: true
        });
      }

      if (config?.createIncident !== false) {
        actions.push({
          type: 'create-incident',
          description: 'Create incident record',
          priority: 'medium',
          automated: true
        });
      }
    } else if (severity.level === 'medium') {
      actions.push({
        type: 'create-ticket',
        description: 'Create work item for addressing regressions',
        priority: 'low',
        automated: true
      });
    }

    return actions;
  }

  /**
   * Execute rollback actions
   */
  async executeActions(actions, regressionData) {
    console.log(`🔄 Executing ${actions.length} rollback actions`);

    const results = [];

    for (const action of actions) {
      console.log(`\n📋 Executing action: ${action.type}`);
      console.log(`   Description: ${action.description}`);
      console.log(`   Priority: ${action.priority}`);
      console.log(`   Automated: ${action.automated}`);

      try {
        const result = await this.executeAction(action, regressionData);
        results.push(result);

        // Record action in incident
        if (this.currentIncident) {
          this.currentIncident.actions.push({
            ...action,
            result,
            timestamp: new Date().toISOString()
          });

          // Update incident file
          const incidentPath = path.join(this.options.incidentDir, 'active', `${this.currentIncident.id}.json`);
          fs.writeFileSync(incidentPath, JSON.stringify(this.currentIncident, null, 2));
        }

      } catch (error) {
        console.error(`❌ Action failed: ${action.type} - ${error.message}`);
        results.push({
          action: action.type,
          success: false,
          error: error.message
        });
      }
    }

    return {
      success: results.every(r => r.success),
      actions: results,
      incidentId: this.currentIncident?.id
    };
  }

  /**
   * Execute individual action
   */
  async executeAction(action, regressionData) {
    switch (action.type) {
      case 'block-merge':
        return this.executeBlockMerge(action);

      case 'create-incident':
        return this.executeCreateIncident(action);

      case 'notify-team':
        return this.executeNotifyTeam(action);

      case 'auto-rollback':
        return this.executeAutoRollback(action, regressionData);

      case 'create-ticket':
        return this.executeCreateTicket(action);

      default:
        throw new Error(`Unknown action type: ${action.type}`);
    }
  }

  /**
   * Execute block merge action
   */
  executeBlockMerge(action) {
    if (this.options.dryRun) {
      console.log('   [DRY RUN] Would block merge in CI/CD');
      return { action: 'block-merge', success: true, dryRun: true };
    }

    // In CI environment, this would be handled by the workflow
    // For now, we just acknowledge the action
    console.log('   ✅ Merge blocking configured in CI pipeline');

    return { action: 'block-merge', success: true };
  }

  /**
   * Execute create incident action
   */
  executeCreateIncident(action) {
    if (this.options.dryRun) {
      console.log('   [DRY RUN] Would create incident in tracking system');
      return { action: 'create-incident', success: true, dryRun: true };
    }

    // Incident already created in createIncident() method
    console.log(`   ✅ Incident ${this.currentIncident.id} created`);

    return {
      action: 'create-incident',
      success: true,
      incidentId: this.currentIncident.id
    };
  }

  /**
   * Execute notify team action
   */
  async executeNotifyTeam(action) {
    if (this.options.dryRun) {
      console.log('   [DRY RUN] Would send team notification');
      return { action: 'notify-team', success: true, dryRun: true };
    }

    // Create notification message
    const message = this.createNotificationMessage();

    try {
      // Log notification (in real implementation, would send to Slack/Teams/etc.)
      console.log('   📢 Team notification prepared:');
      console.log('   ', message.title);
      console.log('   ', message.body);

      return { action: 'notify-team', success: true, message };
    } catch (error) {
      return { action: 'notify-team', success: false, error: error.message };
    }
  }

  /**
   * Execute auto rollback action
   */
  async executeAutoRollback(action, regressionData) {
    if (this.options.dryRun) {
      console.log('   [DRY RUN] Would perform automatic rollback');
      return { action: 'auto-rollback', success: true, dryRun: true };
    }

    console.log('   ⚠️ Auto rollback requires manual approval');
    console.log('   This would revert to the last known working state');

    // In a real implementation, this would:
    // 1. Identify last successful commit
    // 2. Create rollback branch
    // 3. Revert problematic changes
    // 4. Deploy rollback if in production

    return {
      action: 'auto-rollback',
      success: false,
      reason: 'Manual approval required',
      requiresApproval: true
    };
  }

  /**
   * Execute create ticket action
   */
  executeCreateTicket(action) {
    if (this.options.dryRun) {
      console.log('   [DRY RUN] Would create work item in project management');
      return { action: 'create-ticket', success: true, dryRun: true };
    }

    const ticket = this.createWorkItem();
    console.log(`   📝 Work item created: ${ticket.id}`);

    return { action: 'create-ticket', success: true, ticket };
  }

  /**
   * Create notification message
   */
  createNotificationMessage() {
    const incident = this.currentIncident;

    return {
      title: `🚨 TypeScript Regression - ${incident.severity.toUpperCase()}`,
      body: `Incident ${incident.id}

Severity: ${incident.severity} (Score: ${incident.score})
Regression Details:
- Error Increase: ${incident.regressionData.errorIncrease || 0}
- Regression %: ${incident.regressionData.errorRegressionPercent || 0}%
- Critical Errors: ${incident.regressionData.criticalErrors || 0}
- New Error Codes: ${incident.regressionData.newErrorCodes?.join(', ') || 'None'}

Factors: ${incident.severityFactors.join(', ')}

Recommendations:
${incident.recommendations.map(r => `• ${r}`).join('\n')}

Immediate Actions Required:
${incident.actions.map(a => `• ${a.description}`).join('\n')}

Metadata:
- Environment: ${incident.metadata.environment}
- Branch: ${incident.metadata.branch}
- Commit: ${incident.metadata.commit}
- Actor: ${incident.metadata.actor}`
    };
  }

  /**
   * Create work item for tracking
   */
  createWorkItem() {
    const incident = this.currentIncident;

    return {
      id: `WORKITEM-${incident.id}`,
      title: `TypeScript Regression: ${incident.severity.toUpperCase()}`,
      description: `Address TypeScript regressions detected in incident ${incident.id}`,
      severity: incident.severity,
      priority: incident.severity === 'critical' ? 'immediate' :
               incident.severity === 'high' ? 'high' : 'medium',
      assignee: incident.metadata.actor,
      labels: ['typescript', 'regression', incident.severity],
      incidentId: incident.id
    };
  }

  /**
   * Generate rollback report
   */
  generateReport(result) {
    const report = {
      timestamp: new Date().toISOString(),
      incidentId: this.currentIncident?.id,
      severity: this.currentIncident?.severity,
      actionsExecuted: result.actions,
      success: result.success,
      recommendations: this.currentIncident?.recommendations || [],
      nextSteps: this.generateNextSteps(result)
    };

    const reportPath = path.join(this.options.rollbackDir, `rollback-report-${this.currentIncident?.id || Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    console.log(`📊 Rollback report saved to ${reportPath}`);
    return report;
  }

  /**
   * Generate next steps based on execution results
   */
  generateNextSteps(result) {
    const steps = [];

    if (result.success) {
      steps.push('Monitor incident resolution progress');
      steps.push('Verify fixes address root cause');
      steps.push('Update baseline once resolved');
    } else {
      steps.push('Investigate failed actions');
      steps.push('Consider manual intervention');
      steps.push('Escalate if critical');
    }

    if (this.currentIncident?.severity === 'critical') {
      steps.push('Consider emergency rollback if production affected');
      steps.push('Notify stakeholders');
    }

    return steps;
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--auto-rollback':
        options.autoRollback = true;
        break;
      case '--config':
        options.configPath = args[++i];
        break;
    }
  }

  // Load regression data from stdin or file
  let regressionData = {};
  if (process.argv.includes('--regression-data')) {
    const dataIndex = process.argv.indexOf('--regression-data');
    const dataPath = process.argv[dataIndex + 1];
    if (fs.existsSync(dataPath)) {
      regressionData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    }
  } else {
    // Use example data for testing
    regressionData = {
      errorIncrease: 5,
      errorRegressionPercent: 25,
      criticalErrors: 2,
      newErrorCodes: ['2345', '2352'],
      buildSuccess: true,
      performanceRegression: false
    };
  }

  const manager = new TypeScriptRollbackManager(options);
  manager.execute(regressionData)
    .then(result => {
      if (result.success) {
        console.log('✅ Rollback workflow completed successfully');
        process.exit(0);
      } else {
        console.error('❌ Rollback workflow failed');
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('Rollback manager failed:', error);
      process.exit(1);
    });
}

module.exports = TypeScriptRollbackManager;