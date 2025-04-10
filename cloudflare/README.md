<!-- Cloudflare -->
# Cloudflare Deployment

This repository contains Python code to deploy and manage Cloudflare infrastructure using Pulumi.

## Prerequisites

1. **CI/CD Infra**: Assumes you have a CI/CD Infra deployed with a secrets management solution.
2. **Pulumi CLI**: Install Pulumi CLI from the [official website](https://www.pulumi.com/docs/get-started/install/).
3. **Python**: Ensure Python 3.6+ is installed.
4. **Cloudflare API Token**:
   - **Creating the API Token**: 
     - Log in to your Cloudflare account.
     - Navigate to **My Profile > API Tokens > Create Token**.
     - Select **Custom Token** and define the permissions based on the principle of **least privilege**. Only grant the permissions necessary for this Pulumi deployment (e.g., DNS edit, Zone read).
   - **Using the API Token Securely**: 
     - Store the API token securely in a secrets manager like AWS Secrets Manager, HashiCorp Vault, or GitHub Secrets.
     - Integrate the secrets manager with a CI/CD platform such as GitHub Actions to handle deployments securely.
5. **Pulumi Account**: Sign up for a Pulumi account if you don't have one.
6. **Pulumi Cloudflare Package**: Install the `pulumi_cloudflare` package, version `5.37.1`:
    ```bash
    pip install pulumi_cloudflare==5.37.1
    ```

## Setup

1. **Clone the repository**:
    ```bash
    git clone git@github.com:ZeroVuln-io/freebits.git
    cd freebits
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Pulumi**:
    Initialize Pulumi in your project:
    ```bash
    pulumi login
    pulumi stack init dev
    ```

4. **Set Up CI/CD**:
   - Configure your CI/CD platform (e.g., GitHub Actions) to handle deployments.
   - Store your Cloudflare API token in a secrets manager integrated with your CI/CD platform.
   - Update your CI/CD pipeline configuration to use the secrets manager for securely accessing the API token and executing Pulumi commands.

## Project Structure

- **vars.py**: Holds the variables used across the project.
- **customer_1.py**: Contains the logic specific to Customer 1.
- **__main__.py**: Executes the build tasks for Customer 1 and manages the deployment process.

## Deployment

1. **Push Changes to GitHub**:
   - Simply push your changes to the corresponding GitHub repository.
   - GitHub Actions will automatically trigger the deployment process.


<p align="right">(<a href="#readme-top">back to top</a>)</p>




<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[Pulumi-Cloudflare-Provider]: https://pulumi.com/registry/packages/cloudflare/
