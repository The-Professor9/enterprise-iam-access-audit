-- ============================================================================
-- ENTERPRISE IAM ACCESS GOVERNANCE & COMPLIANCE AUDIT
-- Author: [Your Name]
-- Objective: Detect Orphaned Accounts, Segregation of Duties (SoD) Conflicts,
--            Privilege Creep, and Dormant/Excessive Privileges.
-- ============================================================================

-- 1. CRITICAL RISK: ORPHANED ACCOUNTS (Terminated HR status with active access)
-- Compliance Impact: Violates SOX & ISO 27001 A.9.2.6 (Removal of access rights)
SELECT 
    h.employee_id,
    h.full_name,
    h.department,
    h.employment_status,
    h.termination_date,
    e.application_name,
    e.role_name,
    e.last_login_date
FROM hr_employee_roster h
JOIN system_access_entitlements e ON h.employee_id = e.employee_id
WHERE h.employment_status = 'Terminated';

-- 2. HIGH RISK: SEGREGATION OF DUTIES (SoD) VIOLATION
-- Rule: A user cannot both create vendors (Vendor_Master_Create) AND process 
--       invoices (AP_Invoice_Processor) due to fraudulent payment risk.
SELECT 
    h.employee_id,
    h.full_name,
    h.job_title,
    GROUP_CONCAT(e.role_name, ' + ') AS conflicting_roles
FROM hr_employee_roster h
JOIN system_access_entitlements e ON h.employee_id = e.employee_id
WHERE e.role_name IN ('Vendor_Master_Create', 'AP_Invoice_Processor')
GROUP BY h.employee_id, h.full_name, h.job_title
HAVING COUNT(DISTINCT e.role_name) > 1;

-- 3. MEDIUM RISK: PRIVILEGE CREEP & DORMANT ACCESS (> 90 Days Inactive)
-- Compliance Impact: Violates Principle of Least Privilege (NIST AC-6)
SELECT 
    h.employee_id,
    h.full_name,
    h.job_title,
    e.application_name,
    e.role_name,
    e.last_login_date
FROM hr_employee_roster h
JOIN system_access_entitlements e ON h.employee_id = e.employee_id
WHERE e.last_login_date < '2026-08-20'
  AND h.employment_status = 'Active';

-- 4. HIGH RISK: EXCESSIVE PRIVILEGE / ROLE MISALIGNMENT
-- Rule: Tier-1 Help Desk Technicians should not hold permanent Domain Admin rights.
SELECT 
    h.employee_id,
    h.full_name,
    h.job_title,
    e.application_name,
    e.role_name,
    e.access_level
FROM hr_employee_roster h
JOIN system_access_entitlements e ON h.employee_id = e.employee_id
WHERE h.job_title = 'Help Desk Technician'
  AND e.role_name = 'Domain_Admins';
