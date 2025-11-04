# Disaster Recovery Contacts

## Emergency Contact Information

### Primary Emergency Contacts

| Role | Name | Email | Phone | Slack | Availability |
|------|------|-------|-------|-------|---------------|
| **On-call Engineer** | On-call Team | oncall@cortex.ai | +1-555-CORTEX1 | @oncall | 24/7 |
| **Incident Commander** | Sarah Chen | incident-commander@cortex.ai | +1-555-COMMANDER | @sarah-chen | 24/7 |
| **Technical Lead** | Michael Rodriguez | tech-lead@cortex.ai | +1-555-TECHLEAD | @michael-r | 24/7 |
| **Operations Lead** | Jennifer Liu | ops-lead@cortex.ai | +1-555-OPSLEAD | @jennifer-liu | Business hours |
| **Security Lead** | David Park | security-lead@cortex.ai | +1-555-SECURE | @david-park | 24/7 |

### Management Contacts

| Role | Name | Email | Phone | Slack | Availability |
|------|------|-------|-------|-------|---------------|
| **CTO** | Alex Thompson | cto@cortex.ai | +1-555-CTO | @alex-thompson | 24/7 for emergencies |
| **VP Engineering** | Rachel Green | vp-eng@cortex.ai | +1-555-VPE | @rachel-green | Business hours |
| **Director of Operations** | James Wilson | director-ops@cortex.ai | +1-555-DIRECTOR | @james-wilson | Business hours |
| **Head of Security** | Amanda Foster | head-security@cortex.ai | +1-555-HOSECURITY | @amanda-foster | 24/7 for security incidents |

### Team Contacts

#### Engineering Team
| Role | Name | Email | Phone | Slack |
|------|------|-------|-------|-------|
| **Backend Engineer** | Tom Martinez | backend-eng@cortex.ai | +1-555-BACKEND | @tom-martinez |
| **DevOps Engineer** | Lisa Chen | devops@cortex.ai | +1-555-DEVOPS | @lisa-chen |
| **Database Engineer** | Kevin Zhang | db-eng@cortex.ai | +1-555-DATABASE | @kevin-zhang |
| **Security Engineer** | Maria Garcia | security-eng@cortex.ai | +1-555-SECENG | @maria-garcia |

#### Support Team
| Role | Name | Email | Phone | Slack |
|------|------|-------|-------|-------|
| **Support Manager** | Robert Johnson | support-manager@cortex.ai | +1-555-SUPPORTMGR | @robert-johnson |
| **Senior Support Engineer** | Emily Davis | senior-support@cortex.ai | +1-555-SENIORSUPPORT | @emily-davis |
| **Customer Success** | Patricia Miller | customer-success@cortex.ai | +1-555-CUSTOMER | @patricia-miller |

## External Vendor Contacts

### Cloud Infrastructure

| Vendor | Service | Contact | Email | Phone | Support Portal |
|--------|---------|---------|-------|-------|----------------|
| **AWS** | Primary Cloud Provider | Enterprise Support | aws-support@cortex.ai | 1-800-AWS-HELP | https://console.aws.amazon.com/support |
| **AWS** | Account Manager | John Smith | john.smith@aws.com | +1-555-AWS-REP | N/A |
| **Cloudflare** | DNS/CDN | Enterprise Support | cloudflare@cortex.ai | +1-555-CLOUDFLARE | https://dash.cloudflare.com/support |

### Monitoring & Alerting

| Vendor | Service | Contact | Email | Phone | Support Portal |
|--------|---------|---------|-------|-------|----------------|
| **Datadog** | Monitoring Platform | Support | support@datadoghq.com | +1-555-DATADOG | https://www.datadoghq.com/support |
| **PagerDuty** | Incident Management | Support | support@pagerduty.com | +1-555-PAGERDUTY | https://support.pagerduty.com |
| **Statuspage** | Status Page | Support | support@statuspage.io | +1-555-STATUSPAGE | https://support.statuspage.io |

### Security Services

| Vendor | Service | Contact | Email | Phone | Support Portal |
|--------|---------|---------|-------|-------|----------------|
| **CrowdStrike** | Endpoint Security | Incident Response | incident@crowdstrike.com | +1-555-CROWDSTRIKE | https://www.crowdstrike.com/support |
| **Okta** | Identity Management | Support | support@okta.com | +1-555-OKTA | https://support.okta.com |
| **CloudFlare** | DDoS Protection | Security Team | security@cloudflare.com | +1-555-CFSECURITY | https://www.cloudflare.com/ddos |

### Backup & Recovery

| Vendor | Service | Contact | Email | Phone | Support Portal |
|--------|---------|---------|-------|-------|----------------|
| **Backblaze B2** | Cloud Storage | Support | support@backblaze.com | +1-555-BACKBLAZE | https://www.backblaze.com/contact |
| **AWS S3** | Object Storage | Enterprise Support | aws-support@cortex.ai | 1-800-AWS-HELP | https://console.aws.amazon.com/support |

## Escalation Matrix

### Severity Levels and Response Times

| Severity | Definition | Initial Response | Full Response | Escalation Time |
|----------|------------|-----------------|---------------|-----------------|
| **SEV-0** | Critical Business Impact | 5 minutes | 15 minutes | 15 minutes |
| **SEV-1** | Major Service Outage | 15 minutes | 1 hour | 1 hour |
| **SEV-2** | Service Degradation | 1 hour | 4 hours | 4 hours |
| **SEV-3** | Minor Issue | 4 hours | 24 hours | 24 hours |
| **SEV-4** | General Inquiry | 24 hours | 72 hours | 72 hours |

### Escalation Paths

#### SEV-0/Critical Incidents
1. **Immediate (T+0)**: On-call Engineer + Incident Commander
2. **T+15 minutes**: Technical Lead + Security Lead
3. **T+30 minutes**: CTO + VP Engineering
4. **T+1 hour**: Executive Team + PR/Communications

#### SEV-1/Major Incidents
1. **Immediate (T+0)**: On-call Engineer
2. **T+15 minutes**: Technical Lead
3. **T+1 hour**: Operations Lead + Incident Commander
4. **T+4 hours**: VP Engineering

#### SEV-2/Service Degradation
1. **T+0**: On-call Engineer
2. **T+1 hour**: Technical Lead
3. **T+4 hours**: Operations Lead

## Communication Channels

### Internal Communication

| Channel | Purpose | Access | Frequency |
|---------|---------|--------|-----------|
| **Slack #incidents** | Incident coordination | All staff | Real-time during incidents |
| **Slack #cortex-alerts** | Automated alerts | Engineering team | Real-time |
| **Slack #dr-team** | Disaster recovery planning | DR team members | As needed |
| **Email cortex-alerts@cortex.ai** | Incident notifications | All staff | Incident notifications |
| **War Room (Zoom)** | Critical incident management | Incident team | During major incidents |

### External Communication

| Channel | Purpose | Audience | Activation Criteria |
|---------|---------|----------|-------------------|
| **Status Page** | Public service status | All customers | SEV-1+ incidents |
| **Twitter @cortexstatus** | Service updates | Public | SEV-1+ incidents |
| **Email to customers** | Incident notifications | Affected customers | SEV-1+ incidents with customer impact |
| **Phone notification** | Critical customer alerts | Enterprise customers | SEV-0 incidents |

## Contact Information Management

### Contact Updates

**Update Frequency:**
- **Quarterly**: Review and update all contact information
- **Monthly**: Verify on-call schedules and availability
- **As needed**: Immediate updates for role changes or contact changes

**Responsibility:**
- **Operations Lead**: Maintain internal contact lists
- **HR Department**: Maintain employee contact information
- **IT Department**: Maintain external vendor contacts

### Contact Verification

**Verification Schedule:**
- **Monthly**: Test critical contact methods (phone, Slack, email)
- **Quarterly**: Full contact list verification
- **Annually**: External vendor contact verification

**Verification Process:**
1. **Phone Test**: Call critical contacts to verify availability
2. **Slack Test**: Send test messages to verify responsiveness
3. **Email Test**: Send test emails to verify delivery
4. **Vendor Test**: Verify vendor support contact procedures

## Emergency Procedures

### Immediate Contact Protocol

1. **SEV-0/Critical**: Call +1-555-CORTEX1 immediately
2. **Security Incident**: Call +1-555-SECURE immediately
3. **Data Center Outage**: Call on-call engineer + data center contacts
4. **Legal/Regulatory Issue**: Call legal counsel immediately

### War Room Activation

**Activation Process:**
1. Create Zoom meeting: https://cortex.zoom.us/j/incident-{TIMESTAMP}
2. Notify all required participants via Slack and phone
3. Set up dedicated Slack channel: #incident-{INCIDENT_ID}
4. Establish incident documentation (Google Docs, Confluence, etc.)
5. Activate external vendor support if needed

### Communication Templates

#### Initial Incident Notification
```
INCIDENT ALERT - SEV-{LEVEL}

Service: {SERVICE_NAME}
Issue: {BRIEF_DESCRIPTION}
Impact: {USER_IMPACT}
Status: {CURRENT_STATUS}
Incident ID: {INCIDENT_ID}
Started: {TIMESTAMP}

War Room: {ZOOM_LINK}
Slack Channel: #{CHANNEL_NAME}
Incident Commander: {COMMANDER_NAME}
```

#### Stakeholder Update
```
INCIDENT UPDATE - {INCIDENT_ID}

Severity: {SEVERITY_LEVEL}
Duration: {DURATION}
Current Status: {STATUS}
Impact Assessment: {IMPACT}
Actions Taken: {ACTIONS}
ETA: {ESTIMATED_RESOLUTION}

Next Update: {NEXT_UPDATE_TIME}
Status Page: {STATUS_PAGE_URL}
```

## Geographic Considerations

### Time Zones

| Location | Time Zone | Business Hours | After-Hours Contact |
|----------|-----------|----------------|-------------------|
| **Headquarters (US West)** | PST/PDT | 9:00-17:00 | +1-555-CORTEX1 |
| **European Office** | CET/CEST | 9:00-17:00 | +1-555-CORTEX-EU |
| **Asia Pacific Office** | AEST/AEDT | 9:00-17:00 | +1-555-CORTEX-APAC |

### Regional Contacts

| Region | Primary Contact | Backup Contact | Local Phone |
|--------|-----------------|----------------|-------------|
| **US West** | Sarah Chen | Michael Rodriguez | +1-555-USWEST |
| **US East** | Jennifer Liu | Tom Martinez | +1-555-USEAST |
| **Europe** | David Park | Lisa Chen | +44-20-CORTEX-EU |
| **Asia Pacific** | Amanda Foster | Kevin Zhang | +61-2-CORTEX-APAC |

## Special Circumstances

### Holiday Schedule

**Holiday Coverage:**
- **Enhanced Coverage**: Major holidays (Thanksgiving, Christmas, New Year)
- **Standard Coverage**: Regular business holidays
- **Backup Contacts**: Always have backup contacts available during holidays

### Weekend Coverage

**Weekend Protocol:**
- **On-call Engineer**: Available 24/7
- **Incident Commander**: On call rotation
- **Technical Lead**: Backup on-call support
- **Management**: Available for SEV-0+ incidents

### Travel and Unavailability

**Unavailability Protocol:**
- **Advance Notice**: Provide 2 weeks notice for planned unavailability
- **Backup Designation**: Designate backup contacts during absence
- **Emergency Contact**: Provide emergency contact information
- **Coverage Plan**: Document coverage plan during extended absence

## Compliance and Legal

### Regulatory Contacts

| Regulation | Contact | Email | Phone |
|------------|---------|-------|-------|
| **GDPR** | Data Protection Officer | dpo@cortex.ai | +1-555-GDPR |
| **HIPAA** | Compliance Officer | compliance@cortex.ai | +1-555-HIPAA |
| **SOX** | Audit Committee | audit@cortex.ai | +1-555-AUDIT |

### Legal Counsel

| Firm | Contact | Email | Phone |
|------|---------|-------|-------|
| **Primary Counsel** | TechLaw LLP | legal@techlaw.com | +1-555-LEGAL |
| **Litigation Support** | LitigationHelp | litigation@cortex.ai | +1-555-LITIGATION |
| **IP Counsel** | IPAttorneys | ip@cortex.ai | +1-555-IP |

## Documentation Access

### Contact Database Location

- **Internal Database**: https://contacts.cortex.ai
- **Emergency Sheet**: Google Drive: Emergency Contacts
- **Vendor Directory**: SharePoint: Vendor Contacts
- **On-call Schedule**: PagerDuty: Cortex On-call Schedule

### Access Permissions

- **Full Access**: Operations Lead, HR Manager, IT Director
- **Read Access**: All employees
- **Emergency Access**: All on-call personnel
- **Vendor Access**: Limited to vendor-specific information

## Review and Maintenance

### Monthly Review Checklist

- [ ] Verify on-call schedule accuracy
- [ ] Test critical contact phone numbers
- [ ] Update new hire contact information
- [ ] Remove departed employee contacts
- [ ] Verify vendor contact information
- [ ] Update contact preferences

### Quarterly Review Checklist

- [ ] Full contact list review and update
- [ ] Escalation matrix validation
- [ ] Communication channel testing
- [ ] Geographic contact verification
- [ ] Legal and regulatory contact updates
- [ ] Backup contact designation review

### Annual Review Checklist

- [ ] Complete contact database audit
- [ ] Emergency procedure review
- [ ] Communication template updates
- [ ] Vendor contract and contact review
- [ ] Geographic expansion contact planning
- [ ] Compliance and regulatory contact validation

---

**Document Owner**: Operations Lead
**Last Updated**: 2025-11-04
**Next Review**: 2026-02-04
**Emergency Contact**: +1-555-CORTEX1 (24/7)

**Note**: In case of emergency, call the on-call engineer at +1-555-CORTEX1 immediately. Do not attempt recovery procedures without proper authorization.