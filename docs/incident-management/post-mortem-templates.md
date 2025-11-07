# Post-Mortem Documentation Templates and Procedures

## Overview

This document provides comprehensive templates and procedures for conducting post-incident reviews, documenting findings, and implementing improvements. The goal is to foster a blameless culture focused on learning and continuous improvement.

## 🎯 Post-Mortem Philosophy and Principles

### Core Principles

#### **Blameless Culture**

- Focus on system and process improvements, not individual blame
- Assume everyone acted with good intentions based on available information
- Recognize that complex systems fail in complex ways
- Encourage honest and open discussion of mistakes and near-misses

#### **Learning Orientation**

- Every incident is an opportunity to learn and improve
- Focus on "why" and "how" rather than "who"
- Identify systemic weaknesses and patterns
- Create actionable improvement plans

#### **Transparency**

- Share findings broadly within the organization
- Be open about failures and weaknesses
- Document both successes and areas for improvement
- Build trust through honest communication

#### **Action-Oriented**

- Create specific, measurable, and actionable improvement items
- Assign ownership and timelines for all action items
- Track implementation and effectiveness of improvements
- Close the loop on lessons learned

### Types of Post-Mortems

#### **Full Post-Mortem**

- **When**: SEV-1 and SEV-2 incidents, major SEV-3 incidents
- **Participants**: Full incident response team, stakeholders, leadership
- **Timeline**: Within 5 business days of resolution
- **Format**: Formal presentation + detailed written report

#### **Lightweight Post-Mortem**

- **When**: Standard SEV-3 incidents, significant SEV-4 incidents
- **Participants**: Core technical team, immediate stakeholders
- **Timeline**: Within 3 business days of resolution
- **Format**: Structured document + team discussion

#### **Quick Retrospective**

- **When**: Routine SEV-4 incidents, near-misses
- **Participants**: Immediate team members
- **Timeline**: Within 2 business days of resolution
- **Format**: Brief written summary + team discussion

## 📋 Post-Mortem Templates

### 1. Executive Summary Template

#### **Incident Executive Summary**

```
INCIDENT POST-MORTEM EXECUTIVE SUMMARY
======================================

Incident Overview:
-----------------
Incident ID: INC-[YYYYMMDD]-[NUMBER]
Incident Name: [Brief descriptive title]
Date: [Start Date] - [End Date]
Duration: [X hours Y minutes]
Severity: [SEV-1/SEV-2/SEV-3/SEV-4]

Business Impact:
---------------
• Revenue Impact: [$X,XXX] (estimated)
• Customers Affected: [Number/Percentage]
• SLA Compliance: [Yes/No - Details]
• Brand/Reputation Impact: [Description]
• Regulatory Impact: [If applicable]

Root Cause Summary:
------------------
Primary Cause: [One-sentence summary of root cause]
Contributing Factors: [2-3 key contributing factors]
Systemic Issues: [Any systemic problems identified]

Resolution Summary:
------------------
Time to Resolution: [X hours Y minutes]
Primary Fix: [Brief description of immediate fix]
Service Restoration: [How/when service was restored]
Verification: [How resolution was verified]

Key Learnings:
--------------
• [Learning 1 - most important]
• [Learning 2]
• [Learning 3]

Action Items:
-------------
Critical Actions: [Number] items with [X] completed
Improvement Actions: [Number] items planned
Timeline: [X] items due within 30 days, [Y] items long-term

Prevention Effectiveness:
------------------------
Similar Incidents: [Number of similar incidents in past 12 months]
Trend: [Improving/Stable/Worsening]
New Preventive Measures: [List of new measures implemented]

Leadership Actions Required:
---------------------------
• [Any executive decisions needed]
• [Resource allocation decisions]
• [Policy changes needed]
• [Investment decisions]

Prepared by:
------------
[Name], [Title]
[Date]
```

### 2. Detailed Technical Post-Mortem Template

#### **Comprehensive Incident Post-Mortem**

```
COMPREHENSIVE INCIDENT POST-MORTEM
==================================

Incident Details:
----------------
Incident ID: INC-[YYYYMMDD]-[NUMBER]
Incident Name: [Descriptive title]
Date Range: [Start Date/Time] to [End Date/Time]
Duration: [X hours Y minutes]
Severity Classification: [SEV-1/SEV-2/SEV-3/SEV-4]
Report Date: [Date]
Report Author: [Name/Title]

1. EXECUTIVE SUMMARY
   [2-3 paragraph summary suitable for executive audience]

2. INCIDENT TIMELINE
   All times in UTC
   ----------------
   [DATE] - [TIME]: Incident detection
   [DATE] - [TIME]: Initial triage completed
   [DATE] - [TIME]: Response team activated
   [DATE] - [TIME]: Root cause identified
   [DATE] - [TIME]: Mitigation implemented
   [DATE] - [TIME]: Service restored
   [DATE] - [TIME]: Incident resolved

   Detailed Timeline:
   • [TIME]: [Event description] - [Person/Team responsible]
   • [TIME]: [Event description] - [Person/Team responsible]
   • [TIME]: [Event description] - [Person/Team responsible]
   [... continue with all significant events]

3. IMPACT ASSESSMENT
   ------------------
   Business Impact:
   • Revenue Impact: [$X,XXX estimated]
   • Customer Impact: [X customers affected, Y% of user base]
   • Operational Impact: [Description of operational disruption]
   • SLA Impact: [Which SLAs were affected, breach details]
   • Partner Impact: [Impact on partners/integrations]

   Technical Impact:
   • Systems Affected: [List of all affected systems]
   • Data Impact: [Data loss/corruption, if any]
   • Performance Impact: [Performance degradation details]
   • Security Impact: [Any security implications]

4. ROOT CAUSE ANALYSIS
   --------------------
   Primary Root Cause:
   [Detailed description of the primary root cause]
   Contributing Factors:
   • [Factor 1 with description]
   • [Factor 2 with description]
   • [Factor 3 with description]

   Systemic Issues:
   • [Systemic issue 1]
   • [Systemic issue 2]
   • [Systemic issue 3]

   Why It Happened (5 Whys Analysis):
   1. Why did the incident occur? [Answer]
   2. Why did [answer from 1] happen? [Answer]
   3. Why did [answer from 2] happen? [Answer]
   4. Why did [answer from 3] happen? [Answer]
   5. Why did [answer from 4] happen? [Answer]

5. DETECTION AND RESPONSE
   -----------------------
   Detection:
   • How was the incident detected? [Method/source]
   • Detection time: [Time from occurrence to detection]
   • Monitoring gaps: [What wasn't monitored that should have been]

   Response Effectiveness:
   • Time to initial response: [Duration]
   • Time to effective response: [Duration]
   • Response team composition: [Was the right team available?]
   • Communication effectiveness: [How well did communication work?]
   • Tool effectiveness: [Which tools helped/hindered]

   What Went Well:
   • [Positive aspect 1]
   • [Positive aspect 2]
   • [Positive aspect 3]

   What Could Be Improved:
   • [Improvement area 1]
   • [Improvement area 2]
   • [Improvement area 3]

6. RESOLUTION AND RECOVERY
   -------------------------
   Resolution Approach:
   [Description of how the incident was resolved]

   Immediate Actions Taken:
   • [Action 1] - [When] - [Result]
   • [Action 2] - [When] - [Result]
   • [Action 3] - [When] - [Result]

   Verification Process:
   [How resolution was verified and tested]

   Service Recovery:
   [How services were brought back to normal]

   Post-Incident Monitoring:
   [What monitoring was enhanced post-incident]

7. ACTION ITEMS
   -------------
   Immediate Actions (Within 30 days):
   • [Action Item 1]
     Owner: [Name]
     Due Date: [Date]
     Status: [Not Started/In Progress/Completed]
     Description: [Detailed description]

   • [Action Item 2]
     Owner: [Name]
     Due Date: [Date]
     Status: [Not Started/In Progress/Completed]
     Description: [Detailed description]

   Short-term Improvements (Within 90 days):
   • [Action Item 3]
     Owner: [Name]
     Due Date: [Date]
     Status: [Not Started/In Progress/Completed]
     Description: [Detailed description]

   Long-term Improvements (Beyond 90 days):
   • [Action Item 4]
     Owner: [Name]
     Due Date: [Date]
     Status: [Not Started/In Progress/Completed]
     Description: [Detailed description]

8. PREVENTION MEASURES
   --------------------
   Technical Preventive Measures:
   • [Measure 1 with implementation details]
   • [Measure 2 with implementation details]
   • [Measure 3 with implementation details]

   Process Preventive Measures:
   • [Process improvement 1]
   • [Process improvement 2]
   • [Process improvement 3]

   Monitoring Enhancements:
   • [New monitoring/alert 1]
   • [New monitoring/alert 2]
   • [New monitoring/alert 3]

9. LESSONS LEARNED
   ----------------
   Technical Lessons:
   • [Technical lesson 1]
   • [Technical lesson 2]
   • [Technical lesson 3]

   Process Lessons:
   • [Process lesson 1]
   • [Process lesson 2]
   • [Process lesson 3]

   Organizational Lessons:
   • [Organizational lesson 1]
   • [Organizational lesson 2]
   • [Organizational lesson 3]

10. RECOMMENDATIONS
   -----------------
   Leadership Recommendations:
   • [Recommendation 1 with justification]
   • [Recommendation 2 with justification]
   • [Recommendation 3 with justification]

   Resource Recommendations:
   • [Resource need 1 with justification]
   • [Resource need 2 with justification]
   • [Resource need 3 with justification]

   Policy Recommendations:
   • [Policy change 1 with justification]
   • [Policy change 2 with justification]
   • [Policy change 3 with justification]

11. APPENDICES
   ------------
   Appendix A: Incident Response Team Members
   Appendix B: Related Incidents and Trends
   Appendix C: Technical Logs and Evidence
   Appendix D: Customer Communications
   Appendix E: Financial Impact Calculations
   Appendix F: External Notifications (if applicable)

12. REVIEW AND APPROVAL
   --------------------
   Technical Review: [Name/Title] - [Date/Signature]
   Management Review: [Name/Title] - [Date/Signature]
   Executive Review: [Name/Title] - [Date/Signature]

13. FOLLOW-UP SCHEDULE
   -------------------
   Action Item Review: [Date]
   Effectiveness Assessment: [Date]
   Next Update: [Date]
```

### 3. Lightweight Post-Mortem Template

#### **Streamlined Incident Review**

```
LIGHTWEIGHT INCIDENT POST-MORTEM
================================

Incident Details:
----------------
Incident ID: INC-[YYYYMMDD]-[NUMBER]
Date: [Date]
Duration: [X hours Y minutes]
Severity: [SEV-3/SEV-4]
Report by: [Name/Team]
Date: [Date]

1. Summary
   [1-2 paragraph summary of the incident]

2. Timeline
   • [TIME]: Detection - [What happened]
   • [TIME]: Response started - [Actions taken]
   • [TIME]: Root cause found - [Cause]
   • [TIME]: Fixed - [Resolution]
   • [TIME]: Resolved - [Final status]

3. Impact
   • Customers affected: [Number/description]
   • Services affected: [List]
   • Business impact: [Brief description]

4. Root Cause
   Primary cause: [One sentence description]
   Contributing factors: [List key factors]

5. Resolution
   How it was fixed: [Brief description]
   How we verified: [Brief description]

6. What Went Well
   • [Good thing 1]
   • [Good thing 2]

7. What to Improve
   • [Improvement 1]
   • [Improvement 2]

8. Action Items
   • [Action 1] - Owner: [Name] - Due: [Date]
   • [Action 2] - Owner: [Name] - Due: [Date]
   • [Action 3] - Owner: [Name] - Due: [Date]

9. Follow-up
   Review date: [Date]
   Owner of follow-up: [Name]
```

### 4. Quick Retrospective Template

#### **Fast Incident Review**

```
QUICK INCIDENT RETROSPECTIVE
============================

Incident: INC-[ID] - [Brief title]
Date: [Date]
Duration: [X hours]
Reporter: [Name]

What happened?
--------------
[Brief 1-2 sentence description]

What was the impact?
-------------------
[Quick impact description]

What was the cause?
------------------
[Root cause in one sentence]

What did we do well?
-------------------
• [Good point 1]
• [Good point 2]

What could we do better?
-----------------------
• [Improvement 1]
• [Improvement 2]

Any immediate actions needed?
----------------------------
• [Action 1] - [Owner] - [Timeline]
• [Action 2] - [Owner] - [Timeline]

Next review date: [Date]
```

## 🔄 Post-Mortem Procedures

### 1. Scheduling and Preparation

#### **Timing Guidelines**

| Incident Severity | Post-Mortem Timing     | Participants                            | Duration   |
| ----------------- | ---------------------- | --------------------------------------- | ---------- |
| SEV-1             | Within 5 business days | Full response team + stakeholders       | 2-3 hours  |
| SEV-2             | Within 5 business days | Core response team + key stakeholders   | 1-2 hours  |
| SEV-3             | Within 3 business days | Technical team + immediate stakeholders | 1 hour     |
| SEV-4             | Within 2 business days | Immediate team                          | 30 minutes |

#### **Preparation Checklist**

**Incident Commander Responsibilities:**

- [ ] Schedule post-mortem meeting within required timeframe
- [ ] Invite all necessary participants
- [ ] Send incident timeline and initial data to participants 24 hours in advance
- [ ] Assign note-taker for the meeting
- [ ] Prepare incident data and metrics
- [ ] Book appropriate meeting space/video conference

**Technical Lead Responsibilities:**

- [ ] Compile detailed technical timeline
- [ ] Gather relevant logs, metrics, and screenshots
- [ ] Prepare technical diagrams if helpful
- [ ] Document root cause analysis
- [ ] Identify potential contributing factors

**Participant Responsibilities:**

- [ ] Review incident timeline and data prior to meeting
- [ ] Prepare personal observations and learnings
- [ ] Identify potential improvement areas
- [ ] Come prepared to discuss openly and constructively

### 2. Post-Mortem Meeting Structure

#### **Full Post-Mortem Meeting Agenda (90-120 minutes)**

**Part 1: Incident Overview (15 minutes)**

- Incident Commander presents executive summary
- Review of timeline and key events
- Business impact assessment
- Customer impact overview

**Part 2: Technical Deep Dive (30 minutes)**

- Technical Lead presents root cause analysis
- Review of detection and response effectiveness
- Discussion of technical challenges and solutions
- Review of system behavior during incident

**Part 3: Response Process Review (20 minutes)**

- Review of incident response process
- Communication effectiveness assessment
- Team coordination evaluation
- Tool and system effectiveness review

**Part 4: Learning and Improvement (25 minutes)**

- Brainstorming session on lessons learned
- Identification of systemic issues
- Discussion of potential improvements
- Generation of action items

**Part 5: Action Planning (15 minutes)**

- Prioritization of action items
- Assignment of owners and timelines
- Resource requirement identification
- Follow-up planning

**Part 6: Next Steps (5 minutes)**

- Summary of decisions made
- Communication plan for post-mortem findings
- Follow-up meeting schedule
- Document completion timeline

#### **Lightweight Post-Mortem Meeting Agenda (45-60 minutes)**

**Introduction and Overview (10 minutes)**

- Incident summary presentation
- Timeline review
- Impact assessment

**Root Cause Discussion (15 minutes)**

- Technical root cause analysis
- Contributing factors identification
- Systemic issues discussion

**Lessons Learned (15 minutes)**

- What went well discussion
- Improvement opportunities identification
- Action item brainstorming

**Action Planning (5-10 minutes)**

- Action item prioritization
- Owner assignment
- Timeline establishment

### 3. Documentation Procedures

#### **Document Creation Process**

1. **Initial Draft**: Incident Commander creates initial draft within 24 hours of meeting
2. **Technical Review**: Technical Lead reviews and adds technical details
3. **Management Review**: Manager reviews for business impact and organizational implications
4. **Final Approval**: All stakeholders approve final version
5. **Distribution**: Approved document distributed to all relevant parties

#### **Document Storage and Access**

- **Location**: Centralized document repository (e.g., Confluence, SharePoint)
- **Naming Convention**: `Post-Mortem_INC-[ID]_[Service]_[Date]`
- **Access Control**: Read-only for general organization, edit rights for incident team
- **Retention**: Minimum 3 years, longer for regulatory requirements
- **Indexing**: Tagged by service, severity, date, and root cause categories

#### **Document Components Requirements**

- Executive Summary (required for SEV-1/SEV-2)
- Detailed Timeline (required for all incidents)
- Root Cause Analysis (required for all incidents)
- Action Items (required for all incidents)
- Lessons Learned (required for all incidents)
- Technical Details (required for SEV-1/SEV-2)
- Business Impact Assessment (required for SEV-1/SEV-2)

### 4. Action Item Management

#### **Action Item Categories**

1. **Immediate Actions** (0-30 days)
   - Critical fixes or improvements
   - High-impact monitoring enhancements
   - Process changes to prevent recurrence

2. **Short-term Improvements** (30-90 days)
   - System architecture improvements
   - Tool enhancements
   - Training program updates

3. **Long-term Improvements** (90+ days)
   - Major system redesigns
   - Process overhauls
   - Organizational changes

#### **Action Item Tracking**

- **Tracking System**: Use project management tool (Jira, Asana, etc.)
- **Naming Convention**: `PM-[IncidentID]-[ActionNumber]-[Description]`
- **Required Fields**: Owner, due date, status, priority, description
- **Status Updates**: Weekly updates for in-progress items
- **Closure Requirements**: Verification and sign-off from incident commander

#### **Action Item Review Process**

1. **Weekly Review**: Incident Commander reviews all open action items
2. **Monthly Review**: Management review of high-priority items
3. **Quarterly Review**: Leadership review of improvement trends
4. **Final Sign-off**: Incident Commander verifies completion and effectiveness

### 5. Quality Assurance

#### **Post-Mortem Quality Checklist**

**Content Quality:**

- [ ] Root cause is clearly identified and explained
- [ ] Timeline is accurate and complete
- [ ] Impact assessment is comprehensive
- [ ] Action items are specific and actionable
- [ ] Lessons learned are meaningful and actionable

**Process Quality:**

- [ ] Meeting included all necessary participants
- [ ] Discussion was constructive and blameless
- [ ] All voices were heard and considered
- [ ] Action items have clear ownership and timelines
- [ ] Follow-up process is clearly defined

**Documentation Quality:**

- [ ] Document follows approved template
- [ ] Language is clear and professional
- [ ] Technical details are accurate
- [ ] Executive summary is appropriate for audience
- [ ] Document is properly stored and indexed

#### **Peer Review Process**

1. **Technical Review**: Technical Lead or peer technical expert
2. **Process Review**: Incident Commander or process expert
3. **Business Review**: Manager or business stakeholder
4. **Final Approval**: Department Head or designated approver

## 📊 Post-Mortem Metrics and Analysis

### 1. Key Performance Indicators

#### **Incident Metrics**

- **Mean Time to Resolution (MTTR)**: Average time to resolve incidents by severity
- **Incident Recurrence Rate**: Percentage of incidents that recur within 90 days
- **Post-Mortem Completion Rate**: Percentage of incidents with completed post-mortems
- **Action Item Completion Rate**: Percentage of action items completed on time

#### **Process Metrics**

- **Post-Mortem Timeliness**: Percentage completed within required timeframe
- **Action Item Effectiveness**: Percentage of completed actions that prevent recurrence
- **Learning Integration**: Number of systemic improvements implemented
- **Knowledge Sharing**: Number of post-mortems shared across teams

#### **Quality Metrics**

- **Root Cause Identification**: Percentage with clear root cause identified
- **Action Item Quality**: Average specificity and actionability of action items
- **Document Quality**: Peer review scores and feedback
- **Participant Satisfaction**: Survey results from post-mortem participants

### 2. Trend Analysis

#### **Quarterly Review Process**

1. **Data Collection**: Gather all post-mortem data from the quarter
2. **Pattern Identification**: Look for recurring root causes and systemic issues
3. **Trend Analysis**: Identify improving or worsening trends
4. **Improvement Assessment**: Evaluate effectiveness of implemented improvements
5. **Planning**: Adjust incident response and prevention strategies

#### **Annual Review Process**

1. **Comprehensive Analysis**: Review all incidents and post-mortems from the year
2. **Strategic Assessment**: Evaluate overall incident response effectiveness
3. **Budget Planning**: Identify resource needs for improvements
4. **Process Evolution**: Plan major process improvements based on learnings
5. **Organizational Learning**: Share key learnings across the organization

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2025-01-04
- **Next Review**: 2025-04-04
- **Owner**: Incident Response Team
- **Approval**: Head of Engineering
- **Distribution**: All Technical Teams, Management

## Quick Reference

### Post-Mortem Timing

- SEV-1: Within 5 days, 2-3 hours
- SEV-2: Within 5 days, 1-2 hours
- SEV-3: Within 3 days, 1 hour
- SEV-4: Within 2 days, 30 minutes

### Required Participants

- SEV-1: Full response team + stakeholders
- SEV-2: Core team + key stakeholders
- SEV-3: Technical team + immediate stakeholders
- SEV-4: Immediate team only

### Action Item Timeline

- Immediate: 0-30 days
- Short-term: 30-90 days
- Long-term: 90+ days

---

_This document should be reviewed quarterly and updated based on lessons learned from actual post-mortem processes._
