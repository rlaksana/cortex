# Incident Communication Templates

## Overview

This document provides standardized communication templates for different audiences during incident response scenarios. These templates ensure consistent, timely, and appropriate communication throughout the incident lifecycle.

## 📧 Internal Communication Templates

### 1. Initial Incident Notification

#### **Technical Team Alert**

```
SUBJECT: INCIDENT ALERT - [SEVERITY] - [SERVICE NAME] - [INCIDENT ID]

INCIDENT SUMMARY:
• Incident ID: INC-[YYYYMMDD]-[NUMBER]
• Severity: [SEV-1/SEV-2/SEV-3/SEV-4]
• Service(s) Affected: [LIST OF SERVICES]
• First Detected: [TIMESTAMP] UTC
• Current Status: [STATUS]

INITIAL ASSESSMENT:
• Impact: [BRIEF IMPACT DESCRIPTION]
• Affected Users: [ESTIMATED NUMBER/PERCENTAGE]
• Geographic Impact: [REGIONS AFFECTED]
• Business Impact: [REVENUE/OPERATIONAL IMPACT]

IMMEDIATE ACTIONS:
• [Action 1]
• [Action 2]
• [Action 3]

RESPONSE TEAM:
• Incident Commander: [NAME] ([CONTACT])
• Technical Lead: [NAME] ([CONTACT])
• Communications Lead: [NAME] ([CONTACT])

NEXT UPDATE: [TIMESTAMP] UTC
WAR ROOM: [MEETING LINK/CONFERENCE ROOM]

KEY LINKS:
• Incident Dashboard: [LINK]
• Status Page: [LINK]
• Runbook: [LINK]

PLEASE ACKNOWLEDGE RECEIPT IN #incidents SLACK CHANNEL
```

#### **Management Alert**

```
SUBJECT: INCIDENT NOTIFICATION - [SEVERITY] - [SERVICE NAME]

EXECUTIVE SUMMARY:
• Incident ID: INC-[YYYYMMDD]-[NUMBER]
• Severity: [SEV-1/SEV-2/SEV-3/SEV-4]
• Time Detected: [TIMESTAMP] UTC
• Business Impact: [HIGH/MEDIUM/LOW]

CURRENT SITUATION:
• Service(s) Affected: [LIST OF CRITICAL SERVICES]
• Customer Impact: [DESCRIPTION OF IMPACT]
• Revenue Impact: [ESTIMATED DAILY/HOURLY IMPACT]
• SLA Impact: [YES/NO - WHICH SLAS]

RESPONSE STATUS:
• Team Activated: [YES/NO]
• Investigation Status: [STATUS]
• Estimated Resolution: [TIMEFRAME]
• Customer Communications: [PLANNED/SENT]

IMMEDIATE ACTIONS TAKEN:
• [Action 1]
• [Action 2]
• [Action 3]

STAKEHOLDER IMPACT:
• Customers: [IMPACT DESCRIPTION]
• Partners: [IMPACT DESCRIPTION]
• Internal Teams: [IMPACT DESCRIPTION]

NEXT UPDATE: [TIMESTAMP] UTC
CONTACT: Incident Commander [NAME] at [PHONE/EMAIL]
```

### 2. Status Update Templates

#### **Regular Technical Status Update**

```
SUBJECT: STATUS UPDATE - INC-[ID] - [SERVICE NAME] - [TIME]

CURRENT STATUS:
• Incident ID: INC-[YYYYMMDD]-[NUMBER]
• Time: [TIMESTAMP] UTC
• Duration: [X hours Y minutes]
• Status: [INVESTIGATING/IDENTIFIED/MONITORING/RESOLVED]

PROGRESS UPDATE:
• Investigation Findings: [KEY DISCOVERIES]
• Root Cause Status: [IDENTIFIED/IN PROGRESS/UNKNOWN]
• Actions Taken: [LIST OF RECENT ACTIONS]
• Current Impact: [UPDATED IMPACT ASSESSMENT]

NEXT STEPS:
• [Next action 1]
• [Next action 2]
• [Next action 3]

BLOCKERS/CHALLENGES:
• [Any obstacles encountered]
• [Additional resources needed]

TEAM STATUS:
• Team Members Involved: [LIST]
• External Support Required: [YES/NO - DETAILS]
• Escalations: [ANY ESCALATIONS MADE]

UPDATED ETA:
• Resolution ETA: [NEW TIMEFRAME]
• Service Restoration ETA: [NEW TIMEFRAME]

NEXT UPDATE: [TIMESTAMP] UTC
```

#### **Management Status Update**

```
SUBJECT: INCIDENT STATUS UPDATE - INC-[ID] - [TIME]

BUSINESS IMPACT UPDATE:
• Incident Duration: [X hours Y minutes]
• Revenue Impact to Date: [$X,XXX]
• Customers Affected: [UPDATED COUNT]
• SLA Compliance Status: [STATUS]

PROGRESS SUMMARY:
• Technical Status: [PLAIN LANGUAGE STATUS]
• Root Cause: [SIMPLE EXPLANATION IF KNOWN]
• Resolution Progress: [PERCENTAGE OR STATUS]
• Current Customer Experience: [DESCRIPTION]

BUSINESS ACTIONS:
• Customer Communications: [SENT/PLANNED]
• Partner Notifications: [STATUS]
• Comp Planning: [STATUS IF APPLICABLE]
• Media Monitoring: [STATUS]

DECISION POINTS:
• [Any business decisions needed]
• [Resource allocation needs]
• [Customer compensation decisions]

UPDATED TIMELINE:
• Full Resolution: [TIMEFRAME]
• Service Recovery: [TIMEFRAME]
• Normal Operations: [TIMEFRAME]

NEXT LEADERSHIP UPDATE: [TIMESTAMP] UTC
INCIDENT COMMANDER: [NAME] - [PHONE]
```

### 3. Resolution Notification

#### **Technical Resolution Announcement**

```
SUBJECT: RESOLVED - INC-[ID] - [SERVICE NAME] - [TIME]

RESOLUTION SUMMARY:
• Incident ID: INC-[YYYYMMDD]-[NUMBER]
• Resolved At: [TIMESTAMP] UTC
• Total Duration: [X hours Y minutes]
• Resolution Status: [FULL/PARTIAL]

ROOT CAUSE:
• Primary Cause: [ROOT CAUSE DESCRIPTION]
• Contributing Factors: [LIST IF ANY]
• Systems Affected: [COMPLETE LIST]

RESOLUTION ACTIONS:
• Immediate Fix: [DESCRIPTION OF FIX]
• Monitoring Enhanced: [YES/NO - DETAILS]
• Preventive Measures: [SHORT-TERM ACTIONS]
• Long-term Fixes: [PLANNED ACTIONS]

VERIFICATION:
• Service Testing: [PASSED/FAILED - DETAILS]
• Performance Validation: [RESULTS]
• Error Rate: [CURRENT vs BASELINE]
• Customer Impact: [RESOLVED/MONITORING]

POST-INCIDENT ACTIONS:
• Monitoring Period: [DURATION]
• Follow-up Required: [YES/NO - WHAT]
• Documentation: [LINK TO INCIDENT REPORT]
• Retro Meeting: [TIME/DATE]

LESSONS LEARNED:
• Key Takeaway 1: [LESSON]
• Key Takeaway 2: [LESSON]
• Immediate Improvements: [LIST]

INCIDENT COMMANDER: [NAME]
TECHNICAL LEAD: [NAME]
```

#### **Business Resolution Announcement**

```
SUBJECT: INCIDENT RESOLVED - [SERVICE NAME] - BUSINESS IMPACT UPDATE

EXECUTIVE SUMMARY:
• Incident: INC-[ID] - [SERVICE NAME]
• Resolved: [TIMESTAMP] UTC
• Duration: [X hours Y minutes]
• Business Impact: [SUMMARY]

FINANCIAL IMPACT:
• Estimated Revenue Loss: [$X,XXX]
• Customer Refunds/Credits: [$X,XXX]
• Emergency Costs: [$X,XXX]
• Total Financial Impact: [$X,XXX]

CUSTOMER IMPACT:
• Total Customers Affected: [NUMBER]
• Customer Communications: [SENT TO X CUSTOMERS]
• Customer Support Volume: [X% INCREASE]
• Customer Satisfaction Impact: [STATUS]

BUSINESS CONTINUITY:
• Service Status: [FULLY RESTORED/MOSTLY RESTORED]
• Backlog Processing: [TIMEFRAME]
• Customer Recovery Actions: [LIST]
• Partner Recovery Actions: [LIST]

STAKEHOLDER COMMUNICATIONS:
• Internal: [COMPLETED]
• Customers: [COMPLETED]
• Partners: [COMPLETED]
• Regulatory: [IF APPLICABLE]

NEXT STEPS:
• Customer Follow-up: [PLAN]
• Process Improvements: [PLAN]
• Financial Review: [PLAN]
• Leadership Review: [TIME/DATE]

CONTACT FOR FOLLOW-UP: [NAME] - [TITLE] - [EMAIL]
```

## 🌐 External Communication Templates

### 1. Customer Communication Templates

#### **Service Disruption Notice - Active Incident**

```
SUBJECT: Service Disruption - [SERVICE NAME]

STATUS UPDATE:
• Service: [SERVICE NAME]
• Status: [UNAVAILABLE/DEGRADED]
• Issue Started: [TIMESTAMP] [TIMEZONE]
• Current Impact: [DESCRIPTION OF IMPACT]

WHAT'S HAPPENING:
We're currently experiencing [technical issue description].
This is affecting [specific functionality/services].

IMPACT ON YOU:
• [Function 1]: [STATUS]
• [Function 2]: [STATUS]
• Data Access: [STATUS]

WHAT WE'RE DOING:
Our technical team is actively working to resolve this issue.
We have [actions being taken].

ESTIMATED RESOLUTION:
• Time to Resolution: [TIMEFRAME]
• Next Update: [SPECIFIC TIME]

WE APOLOGIZE for any disruption this causes to your business.
Thank you for your patience.

For immediate assistance:
• Support Portal: [LINK]
• Status Page: [LINK]
• Contact Support: [PHONE/EMAIL]
```

#### **Data Security Incident Notice**

```
SUBJECT: Important Security Notice Regarding Your Account

Dear [Customer Name],

We are writing to inform you of a security incident that may have affected your account information.

WHAT HAPPENED:
On [DATE], we detected [description of security incident].
Our investigation indicates that [description of what occurred].

WHAT INFORMATION WAS AFFECTED:
The incident may have exposed [list of data types potentially affected].
[Specific details about data exposure].

WHAT WE ARE DOING:
• We have immediately [actions taken to secure systems]
• We have engaged [third-party security experts/legal counsel]
• We are implementing [additional security measures]
• We are notifying [regulatory authorities as required]

WHAT YOU SHOULD DO:
• [Recommended action 1]
• [Recommended action 2]
• [Recommended action 3]
• Monitor your account for suspicious activity

FOR YOUR PROTECTION:
We have [forced password resets/enabled additional monitoring].

FOR MORE INFORMATION:
• FAQs: [LINK]
• Support: [PHONE/EMAIL]
• Security Center: [LINK]

We sincerely apologize for this incident and any concern it may cause.
We are committed to protecting your information and have implemented
additional security measures to prevent similar incidents.

Sincerely,
[Executive Name/Title]
[Company Name]
```

#### **Service Restoration Notice**

```
SUBJECT: Service Restored - [SERVICE NAME]

GOOD NEWS: [SERVICE NAME] is now fully operational!

SERVICE STATUS:
• Service: [SERVICE NAME]
• Status: FULLY OPERATIONAL
• Restored At: [TIMESTAMP] [TIMEZONE]
• Incident Duration: [X hours Y minutes]

WHAT WAS RESOLVED:
[Brief, non-technical explanation of what was fixed]

VERIFICATION COMPLETED:
• All systems tested and verified
• Performance at normal levels
• No data loss detected
• Security validated

FOR YOUR ACCOUNT:
• No action required from you
• All data is secure and intact
• Services are functioning normally
• No impact on billing or subscriptions

COMPENSATION:
[If applicable - describe compensation/credit]
• [Details of compensation offered]
• [How to access compensation]
• [Timeline for compensation]

WE APPRECIATE your patience during this disruption.

If you experience any issues:
• Support Portal: [LINK]
• Status Page: [LINK]
• Contact Support: [PHONE/EMAIL]

Thank you for being our customer.

Best regards,
[Company Name] Team
```

### 2. Partner/B2B Communication Templates

#### **Partner Incident Notification**

```
SUBJECT: Service Incident - Impact to Integration - [SERVICE NAME]

Dear [Partner Name],

This notice is to inform you of a service incident that may impact your integration with [SERVICE NAME].

INCIDENT DETAILS:
• Incident ID: INC-[ID]
• Service: [SERVICE NAME]
• Started: [TIMESTAMP] UTC
• Severity: [SEV-1/SEV-2/SEV-3/SEV-4]
• Status: [ACTIVE/RESOLVED]

INTEGRATION IMPACT:
• API Endpoints Affected: [LIST OF ENDPOINTS]
• Functionality Impact: [DESCRIPTION]
• Error Rates: [INCREASED TO X%]
• Response Times: [INCREASED TO X MS]

RECOMMENDED ACTIONS:
• [Action 1 for partner systems]
• [Action 2 for partner systems]
• [Action 3 for partner systems]

COMMUNICATION TO YOUR CUSTOMERS:
• Recommended messaging: [KEY POINTS TO COMMUNICATE]
• Coordinated communication: [YES/NO - PROCESS]

SUPPORT:
• Dedicated Support: [CONTACT DETAILS]
• Technical Documentation: [LINK]
• Status Page: [LINK]

UPDATES:
• Next update: [TIME]
• Communication channel: [EMAIL/STATUS PAGE]

We apologize for any disruption this causes to your operations and your customers.

Sincerely,
[Name/Title]
[Company Name]
```

#### **Partner Resolution Notice**

```
SUBJECT: RESOLVED - Service Incident - Integration Restored - [SERVICE NAME]

Dear [Partner Name],

The service incident affecting your integration with [SERVICE NAME] has been resolved.

RESOLUTION SUMMARY:
• Incident ID: INC-[ID]
• Resolved: [TIMESTAMP] UTC
• Duration: [X hours Y minutes]
• Integration Status: FULLY OPERATIONAL

VERIFICATION:
• All API endpoints functioning normally
• Response times at baseline levels
• Error rates within normal parameters
• Data integrity validated

POST-INCIDENT RECOMMENDATIONS:
• [Any recommended actions for partner systems]
• [Monitoring recommendations]
• [Follow-up requirements]

BUSINESS IMPACT REVIEW:
• We would like to discuss any business impact this may have caused
• Please contact [RELATIONSHIP MANAGER] to discuss compensation if applicable

CONTINUOUS IMPROVEMENT:
• Root cause analysis completed
• Preventive measures implemented
• Enhanced monitoring deployed

Thank you for your partnership and patience during this incident.

Best regards,
[Name/Title]
[Company Name]
```

### 3. Regulatory/Compliance Templates

#### **GDPR Breach Notification**

```
SUBJECT: Personal Data Breach Notification - Article 33 GDPR

TO: [Data Protection Authority Name]
FROM: [Company Name]
DATE: [DATE]
INCIDENT REFERENCE: INC-[ID]

1. NATURE OF PERSONAL DATA BREACH
• Description: [Detailed description of breach]
• Categories of data affected: [List of data categories]
• Data subjects affected: [Number and categories]
• Likely consequences: [Assessment of impact]

2. CONTACT POINTS
• Data Protection Officer: [Name and contact]
• Privacy Office: [Contact details]
• Other relevant contacts: [List]

3. LIKELY CONSEQUENCES
• Risk to rights and freedoms: [Assessment]
• Potential harm: [Description]
• Mitigation measures taken: [List]

4. MEASURES TAKEN
• Immediate actions: [List]
• Containment measures: [List]
• Protective measures: [List]
• Notification timeline: [Date and time of actions]

5. PREVENTIVE MEASURES
• Short-term measures: [List]
• Long-term improvements: [List]
• Timeline for implementation: [Schedule]

ADDITIONAL INFORMATION:
• [Any additional required information]
• [Supporting documentation attached]

For immediate questions contact:
• [Legal Department Contact]
• [DPO Contact]
```

#### **Industry-Specific Reporting**

```
SUBJECT: Incident Report - [Industry Regulation Reference]

REGULATORY BODY: [Name of regulatory body]
COMPANY: [Company Name]
INCIDENT ID: INC-[ID]
REPORTING PERIOD: [Date range]
INCIDENT DATE: [Date of incident]

INCIDENT CLASSIFICATION:
• Type: [Security/Operational/Compliance]
• Severity: [As defined by regulation]
• Regulatory Impact: [Specific regulatory implications]

INCIDENT DETAILS:
• Timeline: [Detailed incident timeline]
• Root Cause: [Technical/business root cause]
• Impact Assessment: [Regulatory impact assessment]
• Affected Systems: [List of regulated systems]

COMPLIANCE ASSESSMENT:
• Regulatory Requirements Affected: [List]
• Compliance Status: [Current compliance state]
• Violations: [Any regulatory violations]
• Mitigation Timeline: [Schedule for compliance restoration]

CORRECTIVE ACTIONS:
• Immediate Actions: [List]
• Preventive Measures: [List]
• Timeline for Completion: [Schedule]
• Monitoring Plan: [Ongoing compliance monitoring]

CONTACTS:
• Compliance Officer: [Name/Contact]
• Technical Lead: [Name/Contact]
• Executive Sponsor: [Name/Contact]

CERTIFICATION:
I certify that the information provided in this report is accurate and complete to the best of my knowledge.

[Name], [Title]
[Date]
```

## 📱 Social Media and Public Relations Templates

### 1. Social Media Updates

#### **Twitter/X - Initial Incident**

```
[SERVICE NAME] is currently experiencing [technical issue].
Our team is investigating and working to resolve it as quickly as possible.
We apologize for any disruption.

Status: [LINK TO STATUS PAGE]
#Incident #[ServiceName]
```

#### **Twitter/X - Resolution**

```
The issue affecting [SERVICE NAME] has been resolved.
All services are now fully operational.
Thank you for your patience.

More details: [LINK TO BLOG POST/STATUS PAGE]
#Resolved #[ServiceName]
```

#### **LinkedIn - Professional Update**

```
UPDATE: [Service Name] Service Incident Resolution

We experienced a technical issue affecting [Service Name] on [Date].
Our technical team worked diligently to resolve the issue, and all services are now fully operational.

We apologize for any disruption this may have caused our customers and partners.
We're conducting a thorough review to prevent similar incidents in the future.

For detailed information: [Link to status page or blog post]

#IncidentResponse #ServiceStatus #TechnicalOperations #[CompanyName]
```

### 2. Press Release Template

#### **Service Incident Press Release**

```
FOR IMMEDIATE RELEASE

[Company Name] Resolves Service Incident
All Systems Fully Operational, Customer Services Restored

[CITY, STATE] - [Date] - [Company Name] today announced that it has fully resolved a technical issue that affected [Service Name] beginning on [Date]. All systems are now fully operational and customer services have been restored.

The incident, which began at [Time] [Timezone], affected [description of impact]. [Company Name]'s technical team responded immediately, working around the clock to identify and resolve the root cause.

"We sincerely apologize for the disruption this incident caused our customers," said [Executive Name], [Title] of [Company Name]. "Our team worked diligently to restore full service, and we're implementing additional measures to prevent similar incidents in the future."

[Company Name] has taken the following actions:
• [Action 1]
• [Action 2]
• [Action 3]

Customers who experienced service disruption may [compensation/support information]. The company is conducting a thorough review of the incident and will implement additional preventive measures.

About [Company Name]:
[Company boilerplate]

Media Contact:
[Name]
[Title]
[Email]
[Phone]

###
```

## 📊 Communication Planning Worksheets

### 1. Communication Matrix

| Audience       | Communication Method | Frequency   | Content Owner       | Approval Required |
| -------------- | -------------------- | ----------- | ------------------- | ----------------- |
| Technical Team | Slack/Teams          | Real-time   | Incident Commander  | No                |
| Management     | Email/Meeting        | Hourly      | Communications Lead | Yes               |
| Customers      | Email/Status Page    | As needed   | Customer Success    | Yes               |
| Partners       | Email                | As needed   | Partner Management  | Yes               |
| Media          | Press Release        | As needed   | PR/Comms            | Yes               |
| Regulatory     | Formal Report        | As required | Legal/Compliance    | Yes               |

### 2. Communication Checklist

#### **Pre-Incident Preparation**

- [ ] Contact lists verified and updated
- [ ] Communication templates customized
- [ ] Approval workflows established
- [ ] Status page configured
- [ ] Social media access verified
- [ ] Email distribution lists tested

#### **During Incident**

- [ ] Initial notifications sent within timeframes
- [ ] Regular updates scheduled and sent
- [ ] Stakeholder acknowledgments tracked
- [ ] Message consistency maintained
- [ ] Escalation communications prepared
- [ ] Customer sentiment monitored

#### **Post-Incident**

- [ ] Resolution announcements sent
- [ ] Follow-up communications planned
- [ ] Lessons learned documented
- [ ] Communication effectiveness reviewed
- [ ] Templates updated based on experience
- [ ] Stakeholder feedback collected

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2025-01-04
- **Next Review**: 2025-04-04
- **Owner**: Communications Team
- **Approval**: Head of Communications
- **Distribution**: All Incident Response Team Members

## Usage Guidelines

1. **Customize templates** for your specific organization and incident types
2. **Maintain brand voice** consistency across all communications
3. **Ensure regulatory compliance** for all external communications
4. **Test communication channels** regularly
5. **Update contact information** quarterly
6. **Review templates** after each major incident for improvements

---

_These templates should be adapted to your organization's specific needs and approved by appropriate stakeholders before use._
