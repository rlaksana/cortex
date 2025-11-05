# On-Call Roster and Triage Timeline Management

## Overview

This document defines the comprehensive on-call roster management, triage procedures, and escalation protocols for the Cortex Memory MCP incident management system.

## 📅 On-Call Schedule Management

### Rotation Structure

#### **Primary On-Call Rotation**
- **Duration**: 1 week rotations (Monday 8:00 AM - Monday 8:00 AM)
- **Handover**: Sunday 7:00 PM - Monday 8:00 AM overlap period
- **Timezone**: UTC-based coordination with local timezone considerations
- **Coverage**: 24/7/365 coverage required

#### **Secondary/Backup On-Call**
- **Duration**: 1 week rotations, offset from primary
- **Role**: Primary backup and escalation support
- **Activation**: When primary is unavailable or for multi-incident scenarios
- **Response Time**: 15 minutes maximum

#### **Tertiary/Leadership On-Call**
- **Duration**: 1 week rotations
- **Role**: Critical incident escalation and business decisions
- **Activation**: SEV-1 incidents or primary/secondary unavailable
- **Response Time**: 30 minutes maximum

### Team Structure and Roles

#### **Primary On-Call Engineer**
**Responsibilities:**
- First responder for all incoming incidents
- Initial triage and severity assessment
- Incident commander assignment for SEV-2 and below
- Technical investigation and resolution
- Documentation and handover preparation

**Requirements:**
- Minimum 2 years of production experience
- Comprehensive system knowledge
- Strong communication skills
- Decision-making authority for SEV-3/SEV-4 incidents

#### **Secondary On-Call Engineer**
**Responsibilities:**
- Backup support for primary engineer
- Multi-incident coordination
- Knowledge transfer during handover
- Complex technical consultation

**Requirements:**
- Minimum 1 year of production experience
- Cross-functional system knowledge
- Collaborative problem-solving skills

#### **On-Call Manager**
**Responsibilities:**
- SEV-1 and SEV-2 incident command
- Cross-team coordination
- Business impact assessment
- Stakeholder communications
- Resource allocation decisions

**Requirements:**
- Leadership experience
- Business acumen
- Excellent communication skills
- Decision-making authority

### Schedule Management System

#### **Schedule Generation**
```bash
# Generate next quarter schedule
npm run generate-schedule -- --quarter=2025-Q2 --team=primary

# View current schedule
npm run view-schedule -- --week=current

# Request schedule change
npm run request-change -- --date=2025-03-15 --reason=vacation
```

#### **Schedule Rules**
1. **Maximum Consecutive Weeks**: No more than 2 consecutive weeks
2. **Minimum Rest Period**: Minimum 2 weeks between rotations
3. **Holiday Coverage**: Double coverage for major holidays
4. **Timezone Distribution**: Balanced across timezones for global teams
5. **Skill Distribution**: Ensure mixed skill levels on each rotation

#### **Change Management**
1. **Change Request Types**:
   - Vacation/Personal time
   - Training/Conference attendance
   - Emergency unavailability
   - Health-related absences

2. **Approval Workflow**:
   - Submit change request 2+ weeks in advance
   - Team lead review and approval
   - Schedule update and notification
   - Handover coordination

3. **Emergency Changes**:
   - Immediate notification to team lead
   - Secondary engineer automatic promotion
   - Emergency backup activation
   - Post-incident review

## ⚡ Triage Procedures and Priorities

### Initial Triage Workflow

#### **Incident Intake (T-0 minutes)**
1. **Detection Channels**:
   - Automated monitoring alerts
   - User/customer reports
   - Internal team notifications
   - External security notifications

2. **Immediate Actions**:
   - Acknowledge receipt within 5 minutes
   - Create incident record
   - Assess initial severity
   - Notify on-call team

#### **Rapid Assessment (T+0-5 minutes)**
1. **Impact Questions**:
   - Is service degraded or completely down?
   - Are customers affected?
   - Is data at risk?
   - Is revenue impacted?

2. **Scope Questions**:
   - How many users/systems affected?
   - Geographic scope of impact?
   - Service functionality affected?
   - Critical path dependencies?

3. **Urgency Indicators**:
   - Regulatory/compliance implications
   - Media/press attention
   - Customer contractual impact
   - Safety/security concerns

#### **Severity Classification (T+5-10 minutes)**
Use the incident severity matrix (see separate severity classification document) to assign SEV-1 through SEV-4 levels.

### Triage Decision Tree

#### **Service Availability Issues**
```
Is service completely down?
├─ YES → Assess customer impact
│   ├─ Major customers affected → SEV-1
│   ├─ Significant customers affected → SEV-2
│   └─ Limited customers affected → SEV-3
└─ NO → Assess degradation level
    ├─ Major functionality impacted → SEV-2
    ├─ Partial functionality impacted → SEV-3
    └─ Minor functionality impacted → SEV-4
```

#### **Data Security Issues**
```
Is data compromised or at risk?
├─ YES → Assess data sensitivity
│   ├─ PII/Financial data → SEV-1
│   ├─ Confidential business data → SEV-2
│   └─ Non-sensitive data → SEV-3
└─ NO → Assess security controls
    ├─ Security bypass possible → SEV-2
    ├─ Security weakness identified → SEV-3
    └─ Policy violation → SEV-4
```

#### **Performance Issues**
```
Is response time > 10x normal?
├─ YES → Assess business impact
│   ├─ Revenue-generating functions → SEV-1
│   ├─ Critical business functions → SEV-2
│   └─ Non-critical functions → SEV-3
└─ NO → Assess user experience
    ├─ Significant UX degradation → SEV-3
    └─ Minor UX impact → SEV-4
```

### Priority Matrix

#### **Response Time Objectives**
| Severity | Initial Response | First Update | Resolution Target |
|----------|------------------|--------------|-------------------|
| SEV-1 | 5 minutes | 15 minutes | 1 hour |
| SEV-2 | 15 minutes | 1 hour | 4 hours |
| SEV-3 | 1 hour | 4 hours | 24 hours |
| SEV-4 | 4 hours | 24 hours | 72 hours |

#### **Communication Cadence**
| Severity | Management Updates | Technical Sync | Customer Updates |
|----------|-------------------|---------------|------------------|
| SEV-1 | Every 30 minutes | Every 15 minutes | As needed |
| SEV-2 | Every 2 hours | Every hour | Every 4 hours |
| SEV-3 | Every 4 hours | Every 2 hours | Every 12 hours |
| SEV-4 | Every 24 hours | Every 8 hours | As needed |

## 📞 Escalation Paths and Contact Matrix

### Escalation Criteria

#### **Automatic Escalation Triggers**
1. **Time-based Escalation**:
   - No response within response time objective
   - No progress update within communication cadence
   - Resolution time exceeding 150% of target

2. **Impact-based Escalation**:
   - Customer impact increases
   - Additional systems affected
   - Business impact escalates
   - Regulatory implications identified

3. **Resource-based Escalation**:
   - Primary responder overwhelmed
   - Specialized expertise required
   - Cross-functional coordination needed
   - External vendor involvement required

#### **Manual Escalation Triggers**
1. Primary responder judgment call
2. Business stakeholder request
3. Customer escalation
4. Media attention
5. Regulatory requirement

### Escalation Workflow

#### **Level 1: On-Call Engineer → On-Call Manager**
**Trigger Conditions**:
- SEV-1 incidents automatically
- SEV-2 incidents after 1 hour without progress
- Resource requirements beyond authority
- Customer escalations

**Contact Protocol**:
- Immediate phone call for SEV-1
- Phone call within 15 minutes for SEV-2
- Include incident summary and actions taken
- Request specific support needed

#### **Level 2: On-Call Manager → Department Head**
**Trigger Conditions**:
- Multiple SEV-1 incidents
- Business continuity threatened
- Major customer impacts
- Regulatory compliance issues

**Contact Protocol**:
- Immediate notification for business impact
- Include business impact assessment
- Provide resolution timeline
- Request executive support if needed

#### **Level 3: Department Head → C-Suite**
**Trigger Conditions**:
- System-wide outages
- Major data breaches
- Regulatory violations
- Media attention

**Contact Protocol**:
- Immediate executive notification
- Include executive summary
- Provide business continuity plan
- Coordinate crisis communications

### Contact Matrix

#### **Primary Contact List**
```yaml
emergency_contacts:
  primary_on_call:
    name: "Current Primary"
    phone: "+1-XXX-XXX-XXXX"
    email: "oncall-primary@company.com"
    slack: "@oncall-primary"

  secondary_on_call:
    name: "Current Secondary"
    phone: "+1-XXX-XXX-XXXX"
    email: "oncall-secondary@company.com"
    slack: "@oncall-secondary"

  oncall_manager:
    name: "Current Manager"
    phone: "+1-XXX-XXX-XXXX"
    email: "oncall-manager@company.com"
    slack: "@oncall-manager"
```

#### **Escalation Contacts**
```yaml
escalation_contacts:
  engineering_director:
    name: "Engineering Director"
    phone: "+1-XXX-XXX-XXXX"
    email: "eng-director@company.com"
    slack: "@eng-director"

  cto:
    name: "Chief Technology Officer"
    phone: "+1-XXX-XXX-XXXX"
    email: "cto@company.com"
    slack: "@cto"

  ceo:
    name: "Chief Executive Officer"
    phone: "+1-XXX-XXX-XXXX"
    email: "ceo@company.com"
    slack: "@ceo"
```

#### **Cross-Functional Contacts**
```yaml
cross_functional:
  security_team:
    primary: "security-lead@company.com"
    emergency: "+1-XXX-XXX-XXXX"

  legal_team:
    primary: "legal-lead@company.com"
    emergency: "+1-XXX-XXX-XXXX"

  communications:
    primary: "comms-lead@company.com"
    emergency: "+1-XXX-XXX-XXXX"

  customer_support:
    primary: "support-lead@company.com"
    oncall: "+1-XXX-XXX-XXXX"
```

## 🔄 Incident Lifecycle Management

### Incident Phases

#### **Phase 1: Detection and Triage (0-15 minutes)**
1. Incident detection and logging
2. Initial impact assessment
3. Severity classification
4. Team activation
5. Communication setup

#### **Phase 2: Investigation and Assessment (15 minutes - 2 hours)**
1. Detailed impact analysis
2. Root cause investigation
3. Scope determination
4. Resource requirements
5. Communication planning

#### **Phase 3: Resolution and Recovery (2 hours - 72 hours)**
1. Solution implementation
2. Service restoration
3. Verification testing
4. Customer communication
5. Monitoring enhancement

#### **Phase 4: Post-Incident Activities (72 hours+)**
1. Documentation completion
2. Root cause analysis
3. Lessons learned
4. Improvement implementation
5. Knowledge base updates

### Incident Status Tracking

#### **Status Definitions**
- **New**: Incident detected, not yet triaged
- **Triage**: Initial assessment in progress
- **Investigating**: Detailed analysis underway
- **Identified**: Root cause found
- **Monitoring**: Solution implemented, observing
- **Resolved**: Incident resolved, service restored
- **Closed**: Documentation complete, incident archived

#### **Status Transition Rules**
```
New → Triage: Immediate (within 5 minutes)
Triage → Investigating: After initial assessment (within 15 minutes)
Investigating → Identified: When root cause determined
Identified → Monitoring: When solution implemented
Monitoring → Resolved: When service restored (minimum 30 minutes)
Resolved → Closed: After documentation complete (minimum 24 hours)
```

### Handover Procedures

#### **Standard Rotation Handover**
1. **Pre-Handover Preparation** (Sunday 7:00 PM):
   - Review active incidents
   - Update documentation
   - Prepare summary report
   - Test communication channels

2. **Handover Meeting** (Sunday 8:00 PM):
   - Transfer active incidents
   - Review system status
   - Discuss known issues
   - Validate contact information

3. **Post-Handover Validation** (Sunday 8:30 PM):
   - Test notification systems
   - Validate access permissions
   - Confirm monitoring setup
   - Document handover complete

#### **Emergency Handover**
1. **Immediate Notification**: Contact secondary engineer
2. **Incident Transfer**: Provide incident summary and context
3. **Access Transfer**: Ensure proper tool access
4. **Communication Update**: Notify team of handover

### Performance Metrics

#### **Team Performance Indicators**
- **Response Time Compliance**: % incidents meeting response time objectives
- **Resolution Time Compliance**: % incidents meeting resolution targets
- **Escalation Rate**: % incidents requiring escalation
- **Customer Satisfaction**: Post-incident survey scores
- **Team Utilization**: On-call workload distribution

#### **Individual Performance Metrics**
- **Response Time**: Individual response time performance
- **Resolution Quality**: Solution effectiveness and recurrence rate
- **Documentation Quality**: Completeness and accuracy of incident reports
- **Communication Effectiveness**: Stakeholder feedback
- **Knowledge Contribution**: Training and documentation improvements

#### **Continuous Improvement**
1. **Monthly Performance Reviews**
2. **Quarterly Training Assessments**
3. **Annual Process Evaluation**
4. **Bi-annual Schedule Optimization**
5. **Continuous Feedback Collection**

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2025-01-04
- **Next Review**: 2025-04-04
- **Owner**: Operations Team
- **Approval**: Head of Engineering
- **Distribution**: On-Call Team, Engineering Leadership

## Quick Reference

### SEV-1 Incident Response
1. Immediate phone notification to all on-call levels
2. Activate war room within 15 minutes
3. Executive notification within 30 minutes
4. Customer communication as needed

### SEV-2 Incident Response
1. Notify primary and secondary on-call
2. Activate on-call manager within 15 minutes
3. Department head notification if needed
4. Regular status updates

### Handover Checklist
- [ ] Active incidents reviewed
- [ ] Documentation updated
- [ ] Contact information verified
- [ ] Access permissions tested
- [ ] Monitoring validated
- [ ] Handover documented

---

*This document should be reviewed monthly and updated after any major process changes.*