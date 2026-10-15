# Deployable Ring DeskPass path

This is a separate AWS-backed single-site pilot; the local demo in [`../prototype/`](../prototype/) does not depend on it. The deployable path uses Ring Partner APIs, AWS Lambda, API Gateway, SQS, DynamoDB, Amazon Rekognition, Amazon Bedrock, and Amazon Cognito.

> **Current status: not deployed or live-validated.** The configured IAM Identity Center account instance authenticates the CLI, but exposes no AWS account assignment, so the CLI cannot obtain credentials for AWS services. The SAM template validates and a local container build of its Python 3.12 ARM64 Lambda packages succeeds. No Ring simulator/test device is available. For a local recording, run the synthetic demo from the repository [README](../README.md); do not present this folder as a deployed or Ring-validated service.

## What it does

1. Receives Ring `button_press` and `motion_detected` webhooks over HTTPS and verifies the raw request body with the Ring `X-Signature` HMAC.
2. Deduplicates events in DynamoDB and queues them in SQS, returning quickly to Ring.
3. Uses a Ring OAuth refresh token to request an image snapshot, sends it to Rekognition for text detection, and compares text against active, time-bounded visitor records.
4. Saves only the canonical allowlist candidate and score, plus HMAC-signed audit records. Raw OCR is discarded after matching. Possible matches are always `PENDING_REVIEW`; the system never unlocks a door.
5. Requires a Cognito `Receptionists` group member with software-token MFA for API review. The receptionist identity in audit records comes from verified Cognito claims, not a name supplied by the browser.
6. Lets Bedrock produce an optional status-only explanation; no identity, OCR text, or image is sent to Bedrock and it never chooses access.

Snapshots and raw OCR are held only in worker memory and are not persisted or sent to Bedrock. Event and signed audit records expire after the configured retention period (30 days by default). Visitor records are managed separately and must be deactivated or deleted when no longer needed. HMAC signatures make audit records tamper-evident, not immutable; DynamoDB administrators can still alter or delete them.

## Prerequisites

- AWS CLI v2, AWS SAM CLI, Docker, and a bootstrapped AWS account/region.
- Use IAM Identity Center (AWS SSO) or an assumed role for deployment. Do not use long-lived access keys from `.env`.
- Bedrock model access enabled for the selected region and model ID.
- Ring Developer Portal app access, an authorized Ring account/device or official test device, client ID, client secret, a durable OAuth refresh token, and the webhook HMAC key.
- Ring Developer Portal approval for the relevant Partner API access and webhook configuration.

This repository does not include Ring credentials, AWS credentials, a device, a simulator account, or Ring certification. Do not use Ring account username/password as API credentials. The Ring Playground access token expires and is only appropriate for short initial tests.

The official Ring reference and starter are the source of truth for authentication, event payloads, and API behavior:

- [Ring Partner API documentation](https://developer.amazon.com/docs/ring/api-documentation.html)
- [Ring Developer Portal](https://developer.amazon.com/ring/console/apps)
- [AmazonAppDev Ring API Hello World](https://github.com/AmazonAppDev/ring-api-helloworld)

## Install Python dependencies

From this directory, create an isolated Python 3.12 environment and install the dashboard and Lambda development dependencies:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

The Lambda runtime in `template.yaml` is Python 3.12. SAM builds the Lambda package for that runtime; use `sam build` to validate packaging rather than deploying the workstation's Python environment.

## Configure AWS SSO

Configure a named IAM Identity Center profile and sign in:

```powershell
aws configure sso --profile deskpass
$env:AWS_PROFILE = "deskpass"
aws sso login --profile deskpass
aws sts get-caller-identity
```

The identity must be allowed to deploy CloudFormation/SAM resources, create the named Secrets Manager secret, and administer Cognito users/groups. The deployable app does not load the root `.env`; SAM and boto3 use the AWS credential chain.

## Provision Ring secrets

Create an AWS Secrets Manager `SecretString` JSON object containing:

```json
{
  "client_id": "YOUR_RING_CLIENT_ID",
  "client_secret": "YOUR_RING_CLIENT_SECRET",
  "refresh_token": "YOUR_RING_OAUTH_REFRESH_TOKEN",
  "webhook_secret": "YOUR_RING_HMAC_SIGNING_KEY",
  "audit_hmac_key": "A_SEPARATE_RANDOM_KEY_AT_LEAST_32_CHARACTERS"
}
```

Use the AWS Secrets Manager console so the values are entered directly into AWS. The existing local `RING_HMAC_SIGN_KEY` is suitable for `webhook_secret` only if it exactly matches the key configured for this Ring app in the Developer Portal. Generate an independent random `audit_hmac_key`; do not reuse the webhook key. The missing refresh token must come from Ring's approved OAuth flow. Do not paste secrets into chat, issues, source control, or logs.

If using AWS CLI, create the JSON in a protected local file outside the repository, then run:

```powershell
aws secretsmanager create-secret --name ring-deskpass/credentials --secret-string file://C:\secure\ring-credentials.json
```

The worker serializes refresh-token rotation by limiting its concurrency to one. Keep the secret values out of command-line arguments and shell history.

## Build and deploy

Run local validation first:

```powershell
sam validate --lint
sam build
```

Then deploy only after reviewing the generated resources and expected AWS costs:

```powershell
sam deploy --guided
```

Supply the Secrets Manager ARN, a site identifier, retention period, and a Bedrock model enabled in the chosen region. `sam deploy` creates billable AWS resources; enable an AWS Budget before the first deployment. The template creates CloudWatch alarms for Lambda errors and the SQS dead-letter queue, but does not configure email/SNS alarm delivery. Configure alarm notifications and a cost budget in the target account.

Save the stack outputs: `ApiBaseUrl`, `ReceptionistUserPoolId`, `ReceptionistClientId`, `ReceptionistGroupName`, and the DynamoDB table names. Register `ApiBaseUrl` plus `/webhook/ring` in the Ring Developer Portal and subscribe the app to the supported device event types.

### Create receptionist accounts

In the Cognito user pool named for the stack:

1. Create one user per receptionist, with an email address that the site is authorized to use.
2. Add each user to the `Receptionists` group.
3. Issue each person an individual temporary password through the Cognito console. Do not share accounts.
4. On first sign-in, each user sets a permanent password and enrolls an authenticator app. MFA is required by the user pool.

The API authorizer validates Cognito tokens, and the Lambda additionally requires membership in `Receptionists`. A user outside that group cannot list or review events, even with a valid user-pool token.

### Run the receptionist dashboard

Copy `deployable/.env.example` to `deployable/.env`, then set the API URL, AWS region, and public Cognito app-client ID from the stack outputs. This local configuration file is gitignored; it must not contain AWS access keys or Ring secrets.

From `deployable/`, run the dashboard bound to the local machine:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard.py --server.address 127.0.0.1
```

The dashboard signs in directly with Cognito over TLS, supports required TOTP enrollment/challenges, and keeps returned tokens in the server-side Streamlit session. For a shared site deployment, host it behind an HTTPS reverse proxy with access restricted to the facility network; do not expose the Streamlit development server directly to the internet.

After deployment, add only the visitors needed for the site to the `VisitorsTable` output. The seed helper takes a local JSON file and does not upload that file to the repository:

```powershell
python scripts/seed_visitors.py --table <VisitorsTable-output> --site-id main-office --file .\visitors.json
```

Each item needs `visitor_id` and `name`, plus optional `company`, `status` (`ACTIVE` or `INACTIVE`), and `valid_from` / `valid_until` ISO-8601 timestamps. A visitor without a time window remains active until deactivated or removed. An example is in `scripts/visitors.example.json`. Do not use real visitor data for testing unless you have permission and an appropriate retention policy.

## Validate without live accounts

The focused unit tests cover signature validation, event parsing, privacy redaction, conservative matching, and Cognito-group authorization:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The root GitHub Actions workflow repeats dependency checks, tests, compilation, SAM lint, and a containerized ARM64 package build. It does not use AWS credentials and does not deploy resources.

SAM validation and build do not deploy resources or call Ring. Live integration requires Ring's approved OAuth/test-device setup and AWS service permissions; without a simulator or authorized test device, webhook delivery, snapshot retrieval, token refresh, and Ring's exact payload schema remain unverified. Do not represent this code as Ring-certified or production-validated until those tests and the applicable Ring approval/certification are complete.

## Scope and operational limitations

- Single-site configuration; provision one stack per site. This does not implement public multi-customer Ring AppStore account linking.
- No physical lock control. `APPROVED` is only a receptionist-recorded decision.
- The stack has request throttling, an SQS dead-letter queue, 30-day Lambda log retention, and CloudWatch alarms. Alarm notifications, AWS Budgets, incident response, restore drills, and independent security/privacy review still need to be configured and tested.
- Event and audit TTL deletion is asynchronous. The audit table is not an immutable compliance archive.
- Verify Ring's current OAuth, webhook, and snapshot schemas with an authorized test device before a live facility pilot. Obtain applicable Ring approvals and privacy/legal review for visitor imaging and retention.

## Remaining before an AWS pilot

1. Obtain an AWS account assignment and a deployment role through the account administrator; IAM Identity Center browser authentication alone is not AWS service authorization.
2. Start Docker Desktop's Linux engine, then run `sam build --use-container` for the Lambda's Linux ARM64 dependencies.
3. Get Ring-approved OAuth refresh-token and webhook-signing credentials, then validate real signed event delivery and snapshot retrieval with a simulator or authorized test device.
4. Provision the Ring secret and independent audit HMAC key in Secrets Manager; create individual Cognito receptionist accounts and assign them to `Receptionists`.
5. Configure alarm delivery and an AWS Budget, review costs and permissions, then deploy only after the above checks.
6. Complete privacy/security and any Ring certification requirements before using visitor data or describing the service as production-ready.
