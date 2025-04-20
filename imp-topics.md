<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

   * [Compute Engine VM](#compute-engine-vm)
      + [Metadata](#metadata)
      + [OS Login](#os-login)
      + [Shielded VM vs. Confidential VM](#shielded-vm-vs-confidential-vm)
   * [Storage Buckets](#storage-buckets)
      + [**Storage Bucket Signed URLs**:](#storage-bucket-signed-urls)
      + [**Signed Policy Documents**:](#signed-policy-documents)
      + [**Retention Policy**:](#retention-policy)
      + [**Locking Buckets**:](#locking-buckets)
   * [GCloud reserved IP’s](#gcloud-reserved-ips)
   * [Labels, Tags and network tags](#labels-tags-and-network-tags)
   * [Hybrid Connectivity Options](#hybrid-connectivity-options)
   * [Service Account](#service-account)
   * [Load balancers](#load-balancers)
      + [Comparison Table](#comparison-table)
- [Security Related Services](#security-related-services)
   * [Organization Policies](#organization-policies)
      + [Important ones](#important-ones)
   * [(IAM) Identity & Access Management](#iam-identity-access-management)
      + [Some IAM policy services](#some-iam-policy-services)
   * [Identity-Aware Proxy (IAP)](#identity-aware-proxy-iap)
   * [Sensitive data protection / Data loss prevention](#sensitive-data-protection-data-loss-prevention)
   * [Secret Manager](#secret-manager)
   * [Cloud KMS](#cloud-kms)
      + [Envelope Encryption](#envelope-encryption)
   * [Security Command Center](#security-command-center)
   * [DNSSEC](#dnssec)
      + [Implementation Steps](#implementation-steps)
      + [Limitations and Requirements](#limitations-and-requirements)
      + [Resources for Enabling DNSSEC](#resources-for-enabling-dnssec)
      + [Record Set Types Enhanced by DNSSEC](#record-set-types-enhanced-by-dnssec)
- [VPC Network](#vpc-network)
   * [Shared VPC](#shared-vpc)
   * [VPC Peering](#vpc-peering)
   * [VPC Service Controls](#vpc-service-controls)
   * [Access Context manager](#access-context-manager)
- [Logging & Monitoring](#logging-monitoring)
   * [VPC Flow Logs and Packet Mirroring](#vpc-flow-logs-and-packet-mirroring)
   * [Audit logs](#audit-logs)
      + [Types of Audit Logs](#types-of-audit-logs)
   * [Log Query Language](#log-query-language)
   * [Log Analysis in Big Query](#log-analysis-in-big-query)
- [Secure CI/CD Pipeline](#secure-cicd-pipeline)
- [Security Foundation: Blueprint](#security-foundation-blueprint)
- [Best Practices](#best-practices)
   * [Authentication](#authentication)
   * [Firewall rule](#firewall-rule)
   * [Compute Engine](#compute-engine)
   * [Cloud Storage](#cloud-storage)
   * [BigQuery](#bigquery)
- [Some important documents to read](#some-important-documents-to-read)
- [Random Points to remember](#random-points-to-remember)
      + [**Protecting projects with liens**](#protecting-projects-with-liens)

<!-- TOC end -->


<!-- TOC --><a name="compute-engine-vm"></a>
## Compute Engine VM

<!-- TOC --><a name="metadata"></a>
### Metadata

- startup-script-url
- startup-script
- enable-oslogin
- ssh-keys

<!-- TOC --><a name="os-login"></a>
### OS Login

Google Cloud's OS Login is a service that simplifies SSH access management for your virtual machines (VMs) on Compute Engine. It eliminates the need for traditional SSH keys and relies on your existing Google Cloud identity and IAM permissions for secure access.

<!-- TOC --><a name="shielded-vm-vs-confidential-vm"></a>
### Shielded VM vs. Confidential VM

| Feature/Aspect | Shielded VM | Confidential VM |
| --- | --- | --- |
| Purpose | Enhance security and integrity of VMs | Provide additional privacy by encrypting data in use |
| Protection Mechanism | Uses secure boot, vTPM, integrity monitoring | Uses hardware-based Trusted Execution Environment (TEE) for encryption during processing |
| Use Case | Protect against boot-level and kernel-level malware; ensure VM integrity | Protect sensitive data during computation, ideal for confidential data processing |
| Encryption | Ensures integrity, does not encrypt in-use data | Encrypts data in use, along with at-rest and in-transit encryption |
| Key Components | - Secure Boot<br>- vTPM<br>- Integrity Monitoring | - AMD SEV (Secure Encrypted Virtualization)<br>- Intel SGX (Software Guard Extensions) |
| Suitable For | - General VM workloads requiring enhanced security<br>- Workloads needing protection against rootkits and bootkits | - Highly sensitive data processing<br>- Workloads requiring confidentiality in multi-tenant environments |
| Performance Impact | Minimal, mostly dependent on additional security checks | Some performance overhead due to encryption during computation |
| Configuration | - Enable Shielded VMs in VM configuration<br>- Use Shielded VM images | - Use Confidential VM images<br>- Configure Confidential VMs during setup |
| Compliance | Helps meet security compliance for data integrity and protection | Enhances compliance for data privacy regulations like GDPR, HIPAA by protecting data during use |
| Availability | Broad availability across many VM types and regions | Limited to specific VM types and regions, growing support |
| Cost | Standard VM pricing, possibly slight increase for security features | Higher cost due to additional encryption overhead and specialized hardware requirements |

<!-- TOC --><a name="storage-buckets"></a>
## Storage Buckets

<!-- TOC --><a name="storage-bucket-signed-urls"></a>
### **Storage Bucket Signed URLs**:

- Signed URLs provide secure and temporary access to objects in Cloud Storage.
- They are generated using cryptographic signatures and can grant time-limited access to specific resources.
- Useful for sharing private resources securely with external users or applications.

<!-- TOC --><a name="signed-policy-documents"></a>
### **Signed Policy Documents**:

- Signed policy documents allow clients to upload objects directly to a bucket with predefined conditions and permissions.
- Clients sign a policy document containing upload conditions (e.g., object name, content type) using their private key.
- Helps in delegating upload permissions without sharing credentials.

<!-- TOC --><a name="retention-policy"></a>
### **Retention Policy**:

- A retention policy specifies how long objects must be retained in a bucket before they can be deleted.
- Immutable objects can't be modified or deleted until the retention period expires, ensuring data integrity and compliance.
- Useful for regulatory compliance, data governance, and preventing accidental deletion.

<!-- TOC --><a name="locking-buckets"></a>
### **Locking Buckets**:

- Bucket locking allows you to set retention policies that prevent the deletion of objects, even by project owners and administrators.
- Once locked, a bucket's retention policy can't be reduced, ensuring data immutability and compliance with legal requirements.
- Provides an extra layer of data protection against accidental or malicious deletion.

<!-- TOC --><a name="gcloud-reserved-ips"></a>
## GCloud reserved IP’s

- Google Cloud health checking systems (`130.211.0.0/22` and `35.191.0.0/16`)
- Gcloud IAP service IP range  ( `35.235.240.0/20` )

<!-- TOC --><a name="labels-tags-and-network-tags"></a>
## Labels, Tags and network tags

**Network Tags:**

- **Purpose:** Used for assigning firewall rules to GCP resources.
- **Scope:** Network-specific (applied to VMs within a VPC network).
- **Management:** Defined and assigned independently of labels or tags.

**Labels:**

- **Purpose:** Organize and identify resources for easier management and billing.
- **Scope:** Flexible, can be applied to various GCP resources.
- **Definition:** User-defined key-value pairs with arbitrary values.
- **Functionality:** Primarily for search and categorization within GCP projects.
- **Billing:** Can be used to identify resources for cost allocation.

**Tags (GCP Tags):**

- **Purpose:** Advanced resource management and access control.
- **Scope:** Can be applied to various GCP resources.
- **Definition:** Admin-defined key-value pairs with predefined value sets.
- **Management:** Created and managed by project admins.
- **Functionality:**
    - Used for IAM conditions to define granular access control policies for resources.
    - Can be leveraged for cost analysis based on tag values.

<!-- TOC --><a name="hybrid-connectivity-options"></a>
## Hybrid Connectivity Options

| Connection | Provides | Capacity | Requirements | Access Type |
| --- | --- | --- | --- | --- |
| VPN tunnel | Encrypted tunnel to VPC networks through the public internet | 1.5–3 Gbps per tunnel | Remote VPN gateway | Internal IP addresses |
| Dedicated Interconnect | Dedicated, direct connection to VPC networks | 10 Gbps or 100 Gbps per link | Connection in colocation facility | Internal IP addresses |
| Partner Interconnect | Dedicated bandwidth, connection to VPC network through a service provider | 50 Mbps – 50 Gbps per connection | Service provider | Internal IP addresses |
| Cross-Cloud Interconnect | Dedicated physical connection between VPC network and network hosted by service provider | 10 Gbps or 100 Gbps per connection | Primary and redundant ports (Google Cloud and remote cloud service provider) | Internal IP addresses |

<!-- TOC --><a name="service-account"></a>
## Service Account

**Google Managed Examples:**

- Format `PROJECT_NUMBER@cloudservices.gserviceaccount.com`
- Compute Engine Default: `PROJECT_NUMBER-compute@developer.gserviceaccount.com`
- App engine: `PROJECT_ID@appspot.gserviceaccount.com`

<!-- TOC --><a name="load-balancers"></a>
## Load balancers

![Uploading image.png…]()


<!-- TOC --><a name="comparison-table"></a>
### Comparison Table

| Load Balancer Type | Use Case | Supported Traffic | Scope | Key Features |
| --- | --- | --- | --- | --- |
| HTTP(S) Load Balancer | Global web applications | HTTP(S) | Global | Global load balancing, SSL termination, CDN integration |
| SSL Proxy Load Balancer | SSL offloading | SSL | Global | SSL termination, global distribution |
| TCP Proxy Load Balancer | Non-HTTPS TCP traffic | TCP | Global | TCP traffic, SSL termination, global distribution |
| Network Load Balancer | Low latency, high throughput applications | TCP/UDP | Regional | Layer 4 load balancing, regional scope |
| Internal HTTP(S) Load Balancer | Internal web applications, microservices | HTTP(S) | Regional | Internal traffic within VPC, regional scope |
| Internal TCP/UDP Load Balancer | Internal TCP/UDP traffic balancing | TCP/UDP | Regional | Internal traffic within VPC, regional scope |

<!-- TOC --><a name="security-related-services"></a>
# Security Related Services

<!-- TOC --><a name="organization-policies"></a>
## Organization Policies

<!-- TOC --><a name="important-ones"></a>
### Important ones

Sure, here is the list in the requested format:

- **Disable Default Network Creation (`constraints/compute.skipDefaultNetworkCreation`)**
- **Disable External IP for Compute VM (`constraints/compute.vmExternalIpAccess`)**
- **Disable Public Access to Storage Buckets (`constraints/storage.publicAccessPrevention`)**
- **Disable Service Account Key Creation (`constraints/iam.disableServiceAccountKeyCreation`)**
- **Disable Host Project Deletion (`constraints/resourcemanager.preventDeletion`)**

<!-- TOC --><a name="iam-identity-access-management"></a>
## (IAM) Identity & Access Management

In the Cloud IAM world, permissions are represented in the form:

`<service>.<resource>.<verb>`

Example: `iam.roles.create` , `pubsub.topics.publish`

IAM Roles format examples: `roles/iam.organizationRoleAdmin` , `roles/iam.securityReviewer`

<!-- TOC --><a name="some-iam-policy-services"></a>
### Some IAM policy services

- IAM Policy simulator
- IAM polciy analyzer
- IAM polciy troubleshooter
- IAM recommendar

<!-- TOC --><a name="identity-aware-proxy-iap"></a>
## Identity-Aware Proxy (IAP)

**Identity-Aware Proxy (IAP)** is a Google Cloud service that intercepts web requests, authenticates users via Google Identity Service, and authorizes access only to specified users. It can add authenticated user information to request headers.

**Usage**:

- Restrict access to selected users without changing application code.
- Access user identity in the app using headers:
    
    ```python
    pythonCopy code
    user_email = request.headers.get('X-Goog-Authenticated-User-Email')
    user_id = request.headers.get('X-Goog-Authenticated-User-ID')
    ```
    

**Clearing Cookies**:

- To clear IAP login cookies, append `/_gcp_iap/clear_login_cookie` to your home page URL, e.g., `https://iap-example-999999.appspot.com/_gcp_iap/clear_login_cookie`.

<!-- TOC --><a name="sensitive-data-protection-data-loss-prevention"></a>
## Sensitive data protection / Data loss prevention

Data Loss Prevention (DLP) API to inspect, redact, and de-identify sensitive data in Google Cloud.

Google Cloud Platform (GCP) offers various Data Loss Prevention (DLP) techniques to safeguard sensitive information.

De-identification transformations:

- [Redaction](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#redaction): Deletes all or part of a detected sensitive value.
- [Replacement](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#replacement): Replaces a detected sensitive value with a specified surrogate value.
- [Masking](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#masking): Replaces a number of characters of a sensitive value with a specified surrogate character, such as a hash (#) or asterisk (*).
- [Crypto-based tokenization](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#crypto): Encrypts the original sensitive data value using a cryptographic key. Sensitive Data Protection supports several types of tokenization, including transformations that can be reversed, or "re-identified."
- [Bucketing](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#bucketing): "Generalizes" a sensitive value by replacing it with a range of values. (For example, replacing a specific age with an age range, or temperatures with ranges corresponding to "Hot," "Medium," and "Cold.")
- [Date shifting](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#date_shift): Shifts sensitive date values by a random amount of time.
- [Time extraction](https://cloud.google.com/sensitive-data-protection/docs/transformations-reference#time-extract): Extracts or preserves specified portions of date and time values.

The DLP API provides fast, scalable classification and optional redaction for sensitive data elements like credit card numbers, names, social security numbers, passport numbers, and phone numbers. The API supports text and images – just send data to the API or specify data stored on your Cloud Storage, BigQuery, and Cloud Datastore instances.

<!-- TOC --><a name="secret-manager"></a>
## Secret Manager

**Secret Manager** is a Google Cloud service for securely storing and managing sensitive information such as API keys, passwords, and certificates.

**Roles Needed**:

- **Secret Manager Admin**: `roles/secretmanager.admin` – Full control over secrets.
- **Secret Manager Secret Accessor**: `roles/secretmanager.secretAccessor` – Access secret payloads.
- **Secret Manager Viewer**: `roles/secretmanager.viewer` – View secret metadata.

<!-- TOC --><a name="cloud-kms"></a>
## Cloud KMS

**Cloud Key Management Service (Cloud KMS)** is a Google Cloud service that allows you to manage cryptographic keys for your cloud services.

**Roles Needed**:

- **Key Management Admin**: `roles/cloudkms.admin` – Full control over key rings and keys.
- **Key Encrypter/Decrypter**: `roles/cloudkms.cryptoKeyEncrypterDecrypter` – Encrypt and decrypt data.
- **Key Viewer**: `roles/cloudkms.viewer` – View key metadata but not the key material.

**Key Types**:

- **Google-managed keys**: Automatically managed by Google Cloud.
- **Customer-supplied encryption keys (CSEK)**: Keys provided and managed by the customer, not stored in Cloud KMS.
- **Customer-managed encryption keys (CMEK)**: Keys created and managed in Cloud KMS, giving customers more control over key lifecycle.

**Key Rotation**:

- **Symmetric Keys**: Support automatic key rotation.
- **Asymmetric Keys**: Do not support automatic key rotation.

<!-- TOC --><a name="envelope-encryption"></a>
### Envelope Encryption

![Untitled](Untitled%201.png)

[https://cloud.google.com/kms/docs/envelope-encryption](https://cloud.google.com/kms/docs/envelope-encryption)

<!-- TOC --><a name="security-command-center"></a>
## Security Command Center

**Security Command Center (SCC)** is a comprehensive security management and data risk platform for Google Cloud, providing visibility into your assets and their security state.

**Key Features**:

- **Asset Inventory**: Centralized inventory of your Google Cloud assets.
- **Vulnerability Management**: Identifies vulnerabilities in your environment.
- **Threat Detection**: Detects active threats within your environment.
- **Compliance Monitoring**: Monitors compliance with security policies and standards.

**Built-in Services**:

1. **Event Threat Detection**:
    - Real-time detection of security threats such as malware, cryptomining, and suspicious activity.
    - Uses Google's threat intelligence to identify threats.
2. **Security Health Analytics**:
    - Identifies misconfigurations and vulnerabilities in your cloud resources.
    - Provides actionable security insights to improve your security posture.
3. **Container Threat Detection**:
    - Detects threats and vulnerabilities in Google Kubernetes Engine (GKE) clusters.
    - Analyzes container runtime behavior for anomalies.
4. **Web Security Scanner**:
    - Scans web applications for common vulnerabilities, such as cross-site scripting (XSS) and mixed content.
    - Provides detailed reports on security issues.
5. **Access Approval**:
    - Requires explicit approval for Google Cloud administrative actions.
    - Enhances security by ensuring critical actions are authorized.
6. **Security Health Analytics**:
    - Continuously scans for vulnerabilities and compliance issues.
    - Identifies security misconfigurations and compliance violations.

<!-- TOC --><a name="dnssec"></a>
## DNSSEC

- **DNSSEC Authenticity**: Authenticates responses to domain name lookups.
- **Protection**: Prevents spoofing and poisoning attacks, but does not provide privacy protections.

<!-- TOC --><a name="implementation-steps"></a>
### Implementation Steps

1. **DNS Zone Configuration**
    - Enable DNSSEC for the zone in Cloud DNS.
    - Cloud DNS manages DNSSEC keys (DNSKEY records) and  the signing of zone data with resource record digital signatures (RRSIG records).
2. **TLD Registry Configuration**
    - Add a DS(Delegation Signer) record in your TLD registry to authenticate DNSKEY records.
    - Activate DNSSEC at your domain registrar.
3. **DNS Resolver Configuration**
    - Use a DNS resolver that validates DNSSEC-signed domains.
    - Enable validation for individual systems or local caching resolvers.

<!-- TOC --><a name="limitations-and-requirements"></a>
### Limitations and Requirements

- **Registrar and Registry Support**: Both must support DNSSEC for your TLD.
    - Check registrar and TLD registry DNSSEC support.
    - Consider transferring domains to a registrar that supports DNSSEC if necessary.

<!-- TOC --><a name="resources-for-enabling-dnssec"></a>
### Resources for Enabling DNSSEC

- **DNSSEC Documentation**: Refer to your domain registrar and TLD registry documentation.
- **Community Tutorials**: Follow domain registrar-specific instructions from the Google Cloud community.
- **ICANN List**: Confirm DNSSEC support using the ICANN list of domain registrars.

<!-- TOC --><a name="record-set-types-enhanced-by-dnssec"></a>
### Record Set Types Enhanced by DNSSEC

- **CAA Records**: Control which public CAs(certificate authority) can generate certificates for your domain.
- **IPSECKEY Records**: Enable opportunistic encryption through IPsec tunnels.
- **SSHFP Records**: Enable SSH client applications to validate SSH servers.

<!-- TOC --><a name="vpc-network"></a>
# VPC Network

<!-- TOC --><a name="shared-vpc"></a>
## Shared VPC

Shared VPC in Google Cloud allows multiple projects to share a common Virtual Private Cloud (VPC) network, enabling centralized network administration. This setup involves a host project that owns the VPC network and service projects that utilize the shared network resources. By leveraging Shared VPC, organizations can streamline network management, enforce consistent security policies, and optimize resource usage across different teams or departments, while maintaining separate billing and access controls for each project.

<!-- TOC --><a name="vpc-peering"></a>
## VPC Peering

VPC Peering establishes a direct, private networking connection between two VPC networks, allowing instances in each VPC to communicate as if they were part of the same network. This connection is set up by configuring peering connections on both VPC networks, facilitating low-latency, high-bandwidth communication without requiring external IP addresses or VPNs. Importantly, VPC Peering is not transitive; if VPC A is peered with VPC B, and VPC B is peered with VPC C, VPC A and VPC C cannot communicate through the peering connections. VPC Peering is particularly useful for enabling private, internal communication between different projects or environments within Google Cloud, offering a cost-effective and straightforward solution for inter-network connectivity.

<!-- TOC --><a name="vpc-service-controls"></a>
## VPC Service Controls

VPC Service Controls enhance security for Google Cloud services by defining security perimeters around resources and controlling access based on these boundaries. These controls are implemented through service perimeters and access levels, which govern who can access the services within the defined perimeters. By using VPC Service Controls, organizations can significantly reduce the risk of data breaches and exfiltration, ensuring that sensitive data remains protected. This setup is akin to a firewall around VM instances, providing a robust security layer that controls and monitors data access to maintain data security and compliance with regulatory requirements.

<!-- TOC --><a name="access-context-manager"></a>
## Access Context manager

The Access Context Manager in Google Cloud provides fine-grained access control based on attributes like resource labels, device status, and user identity for enforcing security policies. 

e.g. accessing service restricted by vpc service control to access wihtin a project and we want to access from outside of that project like from our computer through google console then we can create access context and then add it to vpc service control

<!-- TOC --><a name="logging-monitoring"></a>
# Logging & Monitoring

<!-- TOC --><a name="vpc-flow-logs-and-packet-mirroring"></a>
## VPC Flow Logs and Packet Mirroring

VPC Flow Logs and Packet Mirroring are two distinct features in Google Cloud that provide insights into network traffic. **VPC Flow Logs** capture metadata about network traffic flowing to and from network interfaces in your VPC, such as source and destination IP addresses, protocol, and port information. This data is useful for network monitoring, troubleshooting, and security analysis. **Packet Mirroring**, on the other hand, provides a deeper level of inspection by capturing the actual packets of network traffic, allowing for full packet capture and analysis. This feature is ideal for use cases requiring detailed packet-level insights, such as intrusion detection and forensic analysis. The main difference between the two is that VPC Flow Logs offer summary-level metadata, while Packet Mirroring provides the full packet data, enabling comprehensive traffic analysis.

<!-- TOC --><a name="audit-logs"></a>
## Audit logs

<!-- TOC --><a name="types-of-audit-logs"></a>
### Types of Audit Logs

1. **Admin Activity Logs**: Records administrative actions that modify resources (e.g., create, update, delete).
2. **Data Access Logs**: Tracks accesses to data within resources (e.g., reading data, API calls).
3. **System Event Logs**: Captures system events within GCP (e.g., VM restarts, service disruptions).
4. **Policy Denied Logs**: Logs events where access was denied due to policy restrictions.

**roles/logging.viewer :** read-only access to Admin Activity, Policy Denied, and System Event audit logs

**roles/logging.privateLogViewer :**  access to all logs in the `_Required` and `_Default` buckets, including Data Access logs

Data access audit logs are disabled by default except the big query.

![Untitled](Untitled%202.png)

<!-- TOC --><a name="log-query-language"></a>
## Log Query Language

```bash
resource.type="gce_subnetwork"
log_name="projects/<INSERT_PROJECT_ID>/logs/compute.googleapis.com%2Fvpc_flows"
### some filters
jsonPayload.connection.src_ip="Internal_IP_Of_default_us_vm"
jsonPayload.connection.dest_port=22
jsonPayload.connection.dest_port=(80 OR 22)
jsonPayload.connection.protocol=17 # udp
```

<!-- TOC --><a name="log-analysis-in-big-query"></a>
## Log Analysis in Big Query

```bash
#standardSQL
SELECT
   jsonPayload.connection.dest_ip,
   resource
FROM
   `flowlogs_dataset.compute_googleapis_com_vpc_flows*` WHERE
   jsonPayload.connection.dest_port = 22
LIMIT 1000
```

<!-- TOC --><a name="secure-cicd-pipeline"></a>
# Secure CI/CD Pipeline

![Untitled](Untitled%203.png)

![Untitled](Untitled%204.png)

<!-- TOC --><a name="security-foundation-blueprint"></a>
# Security Foundation: Blueprint

![Untitled](Untitled%205.png)

<!-- TOC --><a name="best-practices"></a>
# Best Practices

<!-- TOC --><a name="authentication"></a>
## Authentication

- avoid managing permissions on an individual user basis where possible
- you should have no more than 3 org admins

<!-- TOC --><a name="firewall-rule"></a>
## Firewall rule

- Model of least privilege
- Minimize direct exposure to/from the internet (try to avoid using 0.0.0.0/0)
- Prevent ports and protocols form being exposed unnecessarily
- Firewall naming convention: {direction}-{allow/deny}-{service}-{to/from-location}
- Consider service account firewall rules instead of tag-based rules.

<!-- TOC --><a name="compute-engine"></a>
## Compute Engine

- Control access to resources with projects and IAM.
- Isolate machines using multiple networks.
- Securely connect to Google Cloud networks using VPNs or Cloud Interconnect.
- Monitor and audit logs regularly.
- Only allow VMS to be created from approved images.
- Use the Trusted Images Policy to enforce which images can be used in your organization.
- Harden custom OS images to help reduce the surface of vulnerability for the instance.
- Keep your deployed Compute Engine instances updated.
- Run VMS using custom service accounts with appropriate roles.
- Avoid using the default service account.

<!-- TOC --><a name="cloud-storage"></a>
## Cloud Storage

- Don't use personally identifiable information (PII) in bucket names.
- Don't use PII in object names, because object names appear in URLs.
- Set default object ACLs on buckets.
- Use signed URLs to provide access for users with no account.
- Don't allow buckets to be publicly writable.
- Use lifecycle rules to remove sensitive data that is no longer needed.

<!-- TOC --><a name="bigquery"></a>
## BigQuery

- Use IAM roles to separate who can create and manage Datasets versus who can process the data.
    - Be careful when giving all authenticated users access to data.
- Use authorized views to restrict access to sensitive data:
    - Principle of least privilege.
- Use the expiration settings to remove
unneeded tables and partitions.

<!-- TOC --><a name="some-important-documents-to-read"></a>
# Some important documents to read

- [Identity Management for Google Cloud](https://cloud.google.com/iam/docs/google-identities)
- [**Identity management products and features**](https://cloud.google.com/docs/authentication/identity-products)
- [Connecting to Google Cloud: your networking options explained](https://cloud.google.com/blog/products/networking/google-cloud-network-connectivity-options-explained)
- [Cloud Security Basics](https://www.youtube.com/playlist?list=PLIivdWyY5sqLO-4ePY-A2yROgONOA6Cz4) (Playlist)
- [https://cloud.google.com/compliance?hl=en](https://cloud.google.com/compliance?hl=en)
- [https://cloud.google.com/apigee?hl=en](https://cloud.google.com/apigee?hl=en)
- [Configure Private Google Access for on premise](https://cloud.google.com/vpc/docs/configure-private-google-access-hybrid#requirements)

<!-- TOC --><a name="random-points-to-remember"></a>
# Random Points to remember

- The VPC network to which your on-premises network is connected must have appropriate routes for either the `private.googleapis.com` or `restricted.googleapis.com` destination IP ranges. Check [Configure Private Google Access for on premise](https://cloud.google.com/vpc/docs/configure-private-google-access-hybrid#requirements) for more details.

<!-- TOC --><a name="protecting-projects-with-liens"></a>
### **Protecting projects with liens**

In Google Cloud Platform (GCP), a lien is a mechanism that prevents the deletion of critical resources like projects, billing accounts, or folders. It acts as a safeguard to ensure that important resources are not accidentally or maliciously removed.

 Note that removing a lien requires the `resourcemanager.projects.updateLiens` permission, which is part of the `roles/owner` and `roles/resourcemanager.lienModifier` roles.
