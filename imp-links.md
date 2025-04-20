# GCP Cloud Security and Compliance Resources

This README provides a comprehensive list of official Google Cloud Platform (GCP) documentation and best practices around security, compliance, encryption, networking, and IAM to help you design and maintain a secure GCP environment.

## 🛡 Identity and Access Management (IAM)
- [Understanding Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)
- [Creating and Managing Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)
- [Using Service Accounts with Compute Engine](https://cloud.google.com/iam/docs/understanding-service-accounts#using_service_accounts_with_compute_engine)
- [Best Practices for Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts#best_practices)
- [Managing Identities](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#manage-identities)
- [Enable SSO](https://cloud.google.com/identity/solutions/enable-sso)
- [Using Existing Identity Systems with GCP](https://cloud.google.com/blog/products/identity-security/using-your-existing-identity-management-system-with-google-cloud-platform)
- [Delegation Guide - Admin SDK](https://developers.google.com/admin-sdk/directory/v1/guides/delegation)

## 🔐 Encryption and Data Protection
- [Encryption at Rest](https://cloud.google.com/security/encryption-at-rest)
- [Client-Side Encryption in BigQuery](https://cloud.google.com/bigquery/docs/encryption-at-rest#client_side_encryption)
- [Customer-Supplied Keys (CSEK)](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys)
- [Customer-Managed Keys (CMEK)](https://cloud.google.com/storage/docs/encryption/customer-managed-keys)
- [Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption)
- [Default Keys](https://cloud.google.com/storage/docs/encryption/default-keys)

## 🕵️ DLP and Sensitive Data Protection
- [Pseudonymization](https://cloud.google.com/dlp/docs/pseudonymization)
- [Redacting Sensitive Data in Images](https://cloud.google.com/dlp/docs/redacting-sensitive-data-images)
- [Infotypes Reference](https://cloud.google.com/dlp/docs/infotypes-reference)
- [Creating Custom Infotypes](https://cloud.google.com/dlp/docs/creating-custom-infotypes)
- [Inspecting GCS for Sensitive Data](https://cloud.google.com/dlp/docs/inspecting-storage#inspecting-gcs)

## 🌐 Networking and Access Controls
- [VPC Peering](https://cloud.google.com/vpc/docs/vpc-peering)
- [VPC Peering Key Properties](https://cloud.google.com/vpc/docs/vpc-peering#key_properties)
- [Shared VPC Overview](https://cloud.google.com/vpc/docs/shared-vpc)
- [Shared VPC Admin Roles](https://cloud.google.com/vpc/docs/shared-vpc#svc_proj_admins)
- [Private Access Options](https://cloud.google.com/vpc/docs/private-access-options)
- [VPC Firewalls](https://cloud.google.com/vpc/docs/using-firewalls)
- [Service Accounts vs Tags in Firewalls](https://cloud.google.com/vpc/docs/firewalls#service-accounts-vs-tags)
- [NAT Overview](https://cloud.google.com/nat/docs/overview)
- [Best Practices for VPC Design](https://cloud.google.com/solutions/best-practices-vpc-design)
- [Centralized Network Control](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#centralize_network_control)

## 🔒 Identity-Aware Proxy (IAP)
- [IAP Concepts Overview](https://cloud.google.com/iap/docs/concepts-overview)
- [When to Use IAP](https://cloud.google.com/iap/docs/concepts-overview#when_to_use_iap)
- [Signed Headers How-To](https://cloud.google.com/iap/docs/signed-headers-howto)

## 🔍 Security Scanning and Analysis
- [Security Command Center - Web Scanner Overview](https://cloud.google.com/security-command-center/docs/concepts-web-security-scanner-overview#detectors_and_compliance)
- [Security Scanner](https://cloud.google.com/security-scanner/)
- [Scanning Overview](https://cloud.google.com/security-scanner/docs/scanning)
- [Container Security](https://cloud.google.com/containers/security)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs/overview)
- [Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis)

## 🔧 GKE and App Engine Security
- [Dynamic Provisioning with CMEK in GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/dynamic-provisioning-cmek)
- [Security Patching in GKE](https://cloud.google.com/kubernetes-engine/docs/resources/security-patching)
- [App Engine Access Control](https://cloud.google.com/appengine/docs/standard/python/access-control)

## 🔄 Logging and Monitoring
- [Export Stackdriver Logs to Splunk](https://cloud.google.com/solutions/exporting-stackdriver-logging-for-splunk)
- [Audit Logging in Secret Manager](https://cloud.google.com/secret-manager/docs/audit-logging)
- [Configure Export (v2)](https://cloud.google.com/logging/docs/export/configure_export_v2)

## ☁️ Load Balancing and DNS
- [Load Balancing Overview](https://cloud.google.com/load-balancing/docs/load-balancing-overview)
- [TCP Proxy Load Balancing](https://cloud.google.com/load-balancing/docs/load-balancing-overview#tcp-proxy-load-balancing)
- [External vs Internal Load Balancing](https://cloud.google.com/load-balancing/docs/load-balancing-overview#external_versus_internal_load_balancing)
- [SSL Load Balancing](https://cloud.google.com/load-balancing/docs/ssl)
- [DNSSEC in Cloud DNS](https://cloud.google.com/blog/products/gcp/dnssec-now-available-in-cloud-dns)

## 📂 Storage and Lifecycle
- [Bucket Lock](https://cloud.google.com/storage/docs/bucket-lock)
- [Lifecycle Rules](https://cloud.google.com/storage/docs/lifecycle)

## 🔐 Compliance and Regulations
- [PCI DSS in GCP - Overview](https://cloud.google.com/solutions/pci-dss-compliance-in-gcp)
- [PCI DSS - App Engine](https://cloud.google.com/solutions/pci-dss-compliance-in-gcp#app_engine)
- [PCI DSS - Payment Processing Environment](https://cloud.google.com/solutions/pci-dss-compliance-in-gcp#setting_up_your_payment-processing_environment)
- [PCI DSS Shared Responsibility (PDF)](https://cloud.google.com/files/PCI_DSS_Shared_Responsibility_GCP_v32.pdf)
- [FIPS 140-2 Validated](https://cloud.google.com/security/compliance/fips-140-2-validated)

## 📦 Miscellaneous
- [Restricting Image Access](https://cloud.google.com/compute/docs/images/restricting-image-access#trusted_images)
- [Managed Microsoft AD Best Practices](https://cloud.google.com/managed-microsoft-ad/docs/best-practices)
- [List All Resources](https://cloud.google.com/resource-manager/docs/listing-all-resources)
- [Organization Policy Constraints](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints#constraints-for-specific-services)
- [Using Predefined Roles for Access Control](https://cloud.google.com/resource-manager/docs/access-control-org#using_predefined_roles)
- [Using Existing Identity System with GCP](https://cloud.google.com/blog/products/identity-security/using-your-existing-identity-management-system-with-google-cloud-platform)
- [Protect Users with MFA](https://cloud.google.com/blog/products/identity-security/protect-users-in-your-apps-with-multi-factor-authentication)
- [VPC Service Controls Overview](https://cloud.google.com/vpc-service-controls/docs/overview)
- [VPC Service Controls Homepage](https://cloud.google.com/vpc-service-controls/)

---
