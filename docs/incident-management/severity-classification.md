# Incident Severity Classification System

## Overview

This document defines the comprehensive incident severity classification system (SEV-1 through SEV-4) used to prioritize incident response, allocate resources, and establish appropriate communication protocols. This classification system ensures consistent and effective incident management across the organization.

## 🎯 Severity Classification Framework

### Classification Criteria

All incidents are classified based on four primary criteria:
1. **Business Impact**: Effect on revenue, operations, and strategic objectives
2. **Customer Impact**: Effect on customers, users, and end-user experience
3. **Technical Impact**: Effect on systems, data, and technical infrastructure
4. **Compliance Impact**: Effect on regulatory obligations and legal requirements

### Severity Levels Overview

| Severity | Description | Response Time | Resolution Target | Escalation Level |
|----------|-------------|---------------|-------------------|------------------|
| **SEV-1** | Critical business impact | 5 minutes | 1 hour | Executive level |
| **SEV-2** | Significant business impact | 15 minutes | 4 hours | Management level |
| **SEV-3** | Moderate business impact | 1 hour | 24 hours | Team lead level |
| **SEV-4** | Low business impact | 4 hours | 72 hours | Individual level |

## 🚨 SEV-1: Critical Incidents

### Definition
Incidents with critical impact on business operations, significant customer disruption, major revenue loss, or regulatory compliance violations. These incidents require immediate executive attention and cross-organizational coordination.

### Impact Criteria

#### **Business Impact (Must meet at least ONE)**
- Revenue loss > $10,000 per hour
- Complete service outage for >50% of customers
- Critical business process completely non-functional
- Strategic partnership or contractual breach
- Immediate threat to business continuity

#### **Customer Impact (Must meet at least ONE)**
- Complete service unavailability for all customers
- Data loss or corruption affecting customers
- Security breach exposing customer data
- Critical functionality failure for all users
- Customer safety or legal compliance issues

#### **Technical Impact (Must meet at least ONE)**
- Complete system or infrastructure failure
- Database corruption or permanent data loss
- Security breach or active attack in progress
- Critical third-party dependency failure
- Widespread system compromise

#### **Compliance Impact (Must meet at least ONE)**
- Regulatory compliance violation
- Legal or contractual breach
- Reportable data breach
- Audit failure or compliance gap
- Industry-specific regulatory violation

### Response Requirements

#### **Team Activation**
- **Immediate**: Full incident response team activation
- **Leadership**: Incident Commander (Director level or above)
- **Executive**: C-level notification within 15 minutes
- **Cross-functional**: All relevant departments immediately involved

#### **Communication Cadence**
- **Internal Updates**: Every 15 minutes
- **Management Updates**: Every 30 minutes
- **Executive Updates**: Every 30 minutes
- **Customer Updates**: As needed based on impact

#### **Resolution Timeline**
- **Initial Response**: 5 minutes
- **Assessment Complete**: 15 minutes
- **Solution Implementation**: 45 minutes
- **Total Resolution Target**: 1 hour

### Examples
- Complete service outage
- Data breach exposing customer information
- Production database corruption
- Major security incident
- Regulatory compliance violation
- Critical third-party service failure
- Widespread system compromise

## ⚠️ SEV-2: Significant Incidents

### Definition
Incidents with significant impact on business operations or customer experience that require immediate attention and coordinated response. These incidents affect key business functions or a substantial portion of customers.

### Impact Criteria

#### **Business Impact (Must meet at least ONE)**
- Revenue loss $1,000-$10,000 per hour
- Major service degradation affecting >25% of customers
- Important business process severely impaired
- Customer contract SLA breach
- Significant operational disruption

#### **Customer Impact (Must meet at least ONE)**
- Major service degradation or partial outage
- Critical functionality unavailable for subset of customers
- Performance issues affecting core user experience
- Data access issues for significant customer segment
- Security concern requiring immediate attention

#### **Technical Impact (Must meet at least ONE)**
- Major system component failure
- Significant performance degradation
- Database performance issues or partial unavailability
- Security vulnerability requiring immediate patching
- Multiple service dependencies affected

#### **Compliance Impact (Must meet at least ONE)**
- Potential compliance violation
- Near-miss security incident
- Audit finding requiring immediate action
- Reportable incident if not resolved quickly
- Customer contractual obligations at risk

### Response Requirements

#### **Team Activation**
- **Immediate**: Core incident response team activation
- **Leadership**: Incident Commander (Manager level or above)
- **Management**: Department head notification within 1 hour
- **Cross-functional**: Relevant teams involved as needed

#### **Communication Cadence**
- **Internal Updates**: Every 1 hour
- **Management Updates**: Every 2 hours
- **Customer Updates**: Every 4 hours or as needed
- **Partner Updates**: As needed

#### **Resolution Timeline**
- **Initial Response**: 15 minutes
- **Assessment Complete**: 1 hour
- **Solution Implementation**: 3 hours
- **Total Resolution Target**: 4 hours

### Examples
- Major service degradation
- Critical feature unavailable
- Significant performance issues
- Database performance problems
- Security vulnerability requiring immediate patch
- Customer data access issues
- Third-party dependency failure

## 📋 SEV-3: Moderate Incidents

### Definition
Incidents with moderate impact on business operations or customer experience that require timely response and resolution. These incidents affect some customers or non-critical business functions.

### Impact Criteria

#### **Business Impact (Must meet at least ONE)**
- Revenue loss $100-$1,000 per hour
- Minor service degradation affecting <25% of customers
- Non-critical business process impaired
- Internal productivity impact
- Minor operational disruption

#### **Customer Impact (Must meet at least ONE)**
- Minor service degradation or intermittent issues
- Non-critical functionality unavailable
- Performance issues affecting some users
- Inconvenience but workable issues
- Limited customer impact

#### **Technical Impact (Must meet at least ONE)**
- Single system component failure
- Minor performance degradation
- Background processing issues
- Non-critical feature failure
- Monitoring or reporting issues

#### **Compliance Impact (Must meet at least ONE)**
- Minor compliance concerns
- Documentation gaps
- Process deviations
- Low-risk security issues
- Audit recommendations

### Response Requirements

#### **Team Activation**
- **Standard**: On-call team response
- **Leadership**: Team lead or senior engineer
- **Management**: Notification as needed
- **Cross-functional**: Limited involvement as needed

#### **Communication Cadence**
- **Internal Updates**: Every 4 hours
- **Management Updates**: Every 8 hours or as needed
- **Customer Updates**: Every 12 hours or as needed
- **Status Page**: Update as needed

#### **Resolution Timeline**
- **Initial Response**: 1 hour
- **Assessment Complete**: 4 hours
- **Solution Implementation**: 20 hours
- **Total Resolution Target**: 24 hours

### Examples
- Minor service degradation
- Non-critical feature issues
- Background processing delays
- Minor performance issues
- Documentation errors
- Monitoring gaps
- Internal tool issues

## 📝 SEV-4: Low Incidents

### Definition
Incidents with minimal business impact that can be addressed through standard operating procedures. These incidents typically affect individual users, have limited customer impact, or represent minor system issues.

### Impact Criteria

#### **Business Impact (Must meet at least ONE)**
- Revenue loss <$100 per hour
- No customer impact or minimal internal impact
- Cosmetic or minor UI issues
- Process inefficiencies
- No operational disruption

#### **Customer Impact (Must meet at least ONE)**
- Individual user issues
- Cosmetic or minor UI problems
- Documentation errors
- Minor inconvenience
- No impact on core functionality

#### **Technical Impact (Must meet at least ONE)**
- Logging or monitoring issues
- Minor bugs or cosmetic issues
- Performance within acceptable range
- Non-critical system issues
- Development or staging environment issues

#### **Compliance Impact (Must meet at least ONE)**
- Documentation improvements
- Process optimization opportunities
- Low-risk security findings
- Best practice recommendations
- Minor policy violations

### Response Requirements

#### **Team Activation**
- **Standard**: Individual assignment
- **Leadership**: Self-managed or team lead oversight
- **Management**: Notification for pattern/trend issues
- **Cross-functional**: Limited or no involvement

#### **Communication Cadence**
- **Internal Updates**: Every 24 hours or as needed
- **Management Updates**: Weekly or for trends
- **Customer Updates**: As needed
- **Documentation**: Update as part of resolution

#### **Resolution Timeline**
- **Initial Response**: 4 hours
- **Assessment Complete**: 24 hours
- **Solution Implementation**: 48 hours
- **Total Resolution Target**: 72 hours

### Examples
- Documentation errors
- Cosmetic UI issues
- Individual user problems
- Minor bug fixes
- Performance optimizations
- Process improvements
- Monitoring enhancements

## 🔄 Severity Classification Process

### Initial Classification

#### **Classification Authority**
- **SEV-1**: Incident Commander or on-call manager can declare
- **SEV-2**: On-call engineer can propose, manager approval
- **SEV-3**: On-call engineer can classify
- **SEV-4**: On-call engineer can classify

#### **Classification Timeline**
- **Initial Assessment**: Within 5 minutes of incident detection
- **Classification Confirmation**: Within 15 minutes of detection
- **Classification Review**: Every 30 minutes for SEV-1/SEV-2, every 2 hours for SEV-3/SEV-4

#### **Classification Decision Tree**
```
Is there immediate business continuity threat?
├─ YES → SEV-1 (Critical)
└─ NO → Is revenue >$10K/hour at risk?
    ├─ YES → SEV-1 (Critical)
    └─ NO → Is revenue >$1K/hour at risk?
        ├─ YES → SEV-2 (Significant)
        └─ NO → Is revenue >$100/hour at risk?
            ├─ YES → SEV-3 (Moderate)
            └─ NO → SEV-4 (Low)
```

### Severity Escalation

#### **Automatic Escalation Triggers**
- **Time-based**: Resolution time exceeding 150% of target
- **Impact-based**: Customer impact increasing beyond initial assessment
- **Scope-based**: Additional systems or customers affected
- **Business-based**: Revenue impact exceeding classification threshold

#### **Manual Escalation Process**
1. **Request**: Any team member can request severity reclassification
2. **Assessment**: Incident Commander evaluates against criteria
3. **Decision**: Severity adjusted based on current impact
4. **Notification**: Team and stakeholders notified of change
5. **Response**: Response plan adjusted to new severity level

#### **Escalation Timelines**
- **SEV-4 to SEV-3**: Immediately upon meeting criteria
- **SEV-3 to SEV-2**: Within 15 minutes of criteria meeting
- **SEV-2 to SEV-1**: Within 5 minutes of criteria meeting

### Severity De-escalation

#### **De-escalation Criteria**
- **Issue Resolution**: Root cause addressed and service restored
- **Impact Reduction**: Business impact reduced below threshold
- **Customer Recovery**: All customers have service restored
- **Verification**: Systems stable for minimum time period

#### **De-escalation Process**
1. **Assessment**: Incident Commander evaluates current state
2. **Verification**: Technical team confirms resolution
3. **Stability Period**: Minimum observation time based on severity
   - SEV-1: 4 hours of stable operation
   - SEV-2: 2 hours of stable operation
   - SEV-3: 1 hour of stable operation
   - SEV-4: 30 minutes of stable operation
4. **Notification**: Team notified of severity reduction
5. **Documentation**: Classification change documented

## 📊 Impact Assessment Framework

### Business Impact Assessment

#### **Revenue Impact Calculation**
```
Hourly Revenue Loss = (Affected Revenue per Hour) × (Impact Percentage)

Impact Percentage Categories:
• Complete Unavailability: 100%
• Major Degradation: 75-99%
• Significant Degradation: 50-74%
• Moderate Degradation: 25-49%
• Minor Degradation: 1-24%
• No Impact: 0%
```

#### **Customer Impact Assessment**
```
Customer Impact Score = (Number of Affected Customers ÷ Total Customers) × 100

Impact Categories:
• Critical: >50% of customers affected
• Significant: 25-50% of customers affected
• Moderate: 10-25% of customers affected
• Minor: 1-10% of customers affected
• Minimal: <1% of customers affected
```

#### **Operational Impact Assessment**
```
Operational Impact Categories:
• Critical: Business-critical processes completely non-functional
• Significant: Major processes severely impaired
• Moderate: Some processes affected but workable
• Minor: Minor inconvenience or inefficiency
• Minimal: No significant operational impact
```

### Technical Impact Assessment

#### **System Impact Matrix**
| System Component | Critical | Major | Moderate | Minor |
|------------------|----------|-------|----------|-------|
| Production Database | SEV-1 | SEV-1 | SEV-2 | SEV-3 |
| Application Servers | SEV-1 | SEV-2 | SEV-3 | SEV-4 |
| API Services | SEV-1 | SEV-2 | SEV-3 | SEV-4 |
| Background Processing | SEV-2 | SEV-3 | SEV-3 | SEV-4 |
| Monitoring/Logging | SEV-3 | SEV-3 | SEV-4 | SEV-4 |
| Development Tools | SEV-4 | SEV-4 | SEV-4 | SEV-4 |

#### **Data Impact Assessment**
```
Data Impact Categories:
• Critical: Permanent data loss or corruption affecting customers
• Major: Temporary data loss or significant data corruption
• Moderate: Data access issues or minor corruption
• Minor: Data quality issues or temporary unavailability
• Minimal: No data impact
```

### Compliance Impact Assessment

#### **Regulatory Impact Categories**
```
Compliance Impact Levels:
• Critical: Active regulatory violation or reportable breach
• Major: Potential compliance violation requiring immediate action
• Moderate: Compliance gaps requiring remediation
• Minor: Documentation or process improvements needed
• Minimal: Best practice recommendations
```

#### **Compliance Assessment Matrix**
| Regulation | Critical Impact | Major Impact | Moderate Impact | Minor Impact |
|------------|-----------------|--------------|-----------------|--------------|
| GDPR/Data Protection | SEV-1 | SEV-1 | SEV-2 | SEV-3 |
| SOX/Financial | SEV-1 | SEV-2 | SEV-3 | SEV-4 |
| HIPAA/Healthcare | SEV-1 | SEV-1 | SEV-2 | SEV-3 |
| PCI/DSS | SEV-1 | SEV-2 | SEV-3 | SEV-4 |
| Industry Specific | SEV-1 | SEV-2 | SEV-3 | SEV-4 |

## 📋 Classification Documentation

### Incident Classification Record

#### **Required Information**
```
Incident Classification Record:
- Incident ID: INC-[YYYYMMDD]-[NUMBER]
- Initial Classification: [SEV-X]
- Classification Time: [TIMESTAMP]
- Classification Authority: [NAME/ROLE]
- Justification: [Detailed justification for classification]
- Business Impact: [Specific business impact details]
- Customer Impact: [Specific customer impact details]
- Technical Impact: [Specific technical impact details]
- Compliance Impact: [Specific compliance impact details]
- Revenue Impact: [$X,XXX]
- Customers Affected: [Number/Percentage]
- SLA Impact: [Yes/No - Details]
```

#### **Classification Changes**
```
Severity Change Record:
- From: [SEV-X] To: [SEV-Y]
- Change Time: [TIMESTAMP]
- Change Authority: [NAME/ROLE]
- Change Reason: [Detailed justification for change]
- Impact Changes: [What changed in impact assessment]
- Response Plan Changes: [How response plan was adjusted]
```

### Quality Assurance

#### **Classification Audit Process**
1. **Monthly Review**: Sample of incidents reviewed for classification accuracy
2. **Trend Analysis**: Classification patterns and trends analyzed
3. **Feedback Loop**: Lessons learned fed back into classification process
4. **Training Updates**: Classification guidelines updated based on findings

#### **Classification Metrics**
- **Classification Accuracy**: Percentage of incidents correctly classified
- **Reclassification Rate**: Percentage of incidents requiring severity changes
- **Response Time Compliance**: Percentage meeting response time objectives
- **Resolution Time Compliance**: Percentage meeting resolution targets

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2025-01-04
- **Next Review**: 2025-04-04
- **Owner**: Incident Response Team
- **Approval**: Head of Engineering
- **Distribution**: All Technical Teams, Management

## Quick Reference

### Severity Decision Guide
- **SEV-1**: Business continuity threatened, major revenue loss, data breach
- **SEV-2**: Significant impact, SLA breach, critical functionality affected
- **SEV-3**: Moderate impact, some customers affected, non-critical issues
- **SEV-4**: Minimal impact, individual issues, minor bugs

### Response Time Targets
- **SEV-1**: 5 minutes response, 1 hour resolution
- **SEV-2**: 15 minutes response, 4 hours resolution
- **SEV-3**: 1 hour response, 24 hours resolution
- **SEV-4**: 4 hours response, 72 hours resolution

### Escalation Triggers
- Time exceeding 150% of target
- Impact increasing beyond assessment
- Additional systems/customers affected
- Revenue impact exceeding threshold

---

*This document should be reviewed quarterly and updated based on incident trends and business changes.*