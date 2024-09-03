import pulumi
import pulumi_gcp as gcp

# Vars
gcp_project = "pete_the_cat"

# Naming convention for the secret (example name, but not creating the secret)
secret_name = f"foo_secret_{gcp_project}"

# Create the Secret Manager secret infrastructure
foo_secret = gcp.secretmanager.Secret(
    f"foo_secret_{gcp_project}",
    secret_id=secret_name,
    replication={"automatic": True},
)

# Create a service account
service_account = gcp.serviceaccount.Account(
    f"secret-manager-sa-{gcp_project}",
    account_id=f"secret-manager-sa-{gcp_project}",
    display_name="Secret Manager Service Account"
)

# Create a custom role with the necessary permissions
custom_role = gcp.projects.IAMCustomRole(
    f"custom_role_secret_manager_{gcp_project}",
    role_id=f"customRoleSecretManager{gcp_project}",
    title="Custom Role for Secret Manager Access",
    permissions=[
        "secretmanager.secrets.get",
        "secretmanager.secrets.list",
        "secretmanager.versions.access"
    ],
    project=pulumi.get_project(),
)

# Assign the custom role to the service account
iam_binding_name = f"secretmanager_custom_role_binding_{gcp_project}"
iam_member_binding = gcp.projects.IAMMember(
    iam_binding_name,
    role=custom_role.name,
    member=f"serviceAccount:{service_account.email}",
    project=pulumi.get_project(),
)

# Enable audit logging for Secret Manager to track access and changes
audit_config = gcp.projects.IAMAuditConfig(
    f"audit-config-{gcp_project}",
    project=pulumi.get_project(),
    service="secretmanager.googleapis.com",
    audit_log_configs=[
        {"log_type": "DATA_READ"},
        {"log_type": "DATA_WRITE"},
        {"log_type": "ADMIN_READ"},
    ],
)

# Create an IAM group for managing the service accounts
iam_group = gcp.iam.Group(
    f"iam-group-{gcp_project}",
    group_id=f"secret-manager-{gcp_project}",
    display_name="Secret Manager Group",
)

# Add the service account to the IAM group
group_member = gcp.iam.GroupMember(
    f"group-member-{gcp_project}",
    group=iam_group.name,
    member=service_account.email,
)

# Create a Workload Identity Pool
workload_identity_pool = gcp.iam.WorkloadIdentityPool(
    f"workload-identity-pool-{gcp_project}",
    workload_identity_pool_id=f"workload-identity-pool-{gcp_project}",
    display_name="GitHub Actions Workload Identity Pool"
)

# Create a Workload Identity Provider
workload_identity_provider = gcp.iam.WorkloadIdentityPoolProvider(
    f"workload-identity-provider-{gcp_project}",
    workload_identity_pool_id=workload_identity_pool.workload_identity_pool_id,
    workload_identity_pool_provider_id=f"github-provider-{gcp_project}",
    display_name="GitHub Actions Identity Provider",
    oidc={
        "issuer_uri": "https://token.actions.githubusercontent.com",
        "allowed_audiences": ["https://github.com/myorg/myrepo"],
    }
)

# Bind the service account to the Workload Identity Pool
sa_policy_binding = gcp.serviceaccount.IAMPolicyBinding(
    f"sa-policy-binding-{gcp_project}",
    service_account_id=service_account.id,
    role="roles/iam.workloadIdentityUser",
    member=f"principalSet://iam.googleapis.com/{workload_identity_pool.id}/attribute.repository/myorg/myrepo"
)

# Output the secret resource name and service account email
pulumi.export("secret_name", foo_secret.name)
pulumi.export("service_account_email", service_account.email)
