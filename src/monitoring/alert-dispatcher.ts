// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/**
 * Alert Dispatcher for MCP Cortex
 * Routes notifications to channels (email, Slack, PagerDuty, webhook, SNS, Teams).
 */

export interface DispatchOptions {
  recipients?: string[];
  customHeaders?: Record<string, string>;
  retries?: number;
  backoff?: number;
}

// Helper type to avoid inline arrow signature parsing issues in TS 5.9
type NotificationHandler = (
  message: string,
  config: unknown,
  opts?: DispatchOptions
) => Promise<void>;

/**
 * Alert dispatcher: routes a message+payload to type+config.
 */
export class AlertDispatcher {
  private handlers: Record<string, NotificationHandler> = {
    email: this.sendEmail.bind(this),
    slack: this.sendSlack.bind(this),
    pagerduty: this.sendPagerDuty.bind(this),
    webhook: this.sendWebhook.bind(this),
    sns: this.sendSNS.bind(this),
    teams: this.sendTeams.bind(this),
  };

  async dispatch(
    notificationType: string,
    message: string,
    config: unknown,
    opts?: DispatchOptions
  ): Promise<void> {
    const handler = this.handlers[notificationType];
    if (handler) {
      await handler(message, config, opts);
    } else {
      throw new Error('Unsupported notification type: ' + notificationType);
    }
  }

  private async sendEmail(
    message: string,
    config: unknown,
    _opts?: DispatchOptions
  ): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }

  private async sendSlack(
    message: string,
    config: unknown,
    _opts?: DispatchOptions
  ): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }

  private async sendPagerDuty(
    message: string,
    config: unknown,
    _opts?: DispatchOptions
  ): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }

  private async sendWebhook(
    message: string,
    config: unknown,
    _opts?: DispatchOptions
  ): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }

  private async sendSNS(message: string, config: unknown, _opts?: DispatchOptions): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }

  private async sendTeams(
    message: string,
    config: unknown,
    _opts?: DispatchOptions
  ): Promise<void> {
    const cfg = config as unknown;
    void message;
    void cfg; // stub
  }
}
