# Product Feedback

## Evidence scope

These notes reflect the repository and checks completed through October 15, 2026. The local end-to-end demo uses a custom webhook and synthetic badge; it has not been connected to an official Ring simulator or device. The AWS SAM template and ARM64 Lambda packages were validated locally, but no AWS account resources were deployed. Feedback below distinguishes local tests from unverified live integrations.

## Ring Developer APIs and tooling

- **Used for:** Reviewed Ring Partner API documentation and its Hello World starter while designing the separate `deployable/` path. The deployable code implements Ring OAuth refresh, snapshot requests, and signed-webhook handling, but these calls have not been validated against a Ring account or simulator.
- **What worked:** The published API reference and starter provide a useful starting point for understanding the intended integration.
- **What needs work:** A clearly accessible simulator and durable, end-to-end test credentials would make it possible to verify OAuth refresh, real event payloads, webhook signatures, and snapshot retrieval. The current local synthetic event must be kept distinct from official Ring runtime behavior.
- **Onboarding:** Documentation and sample review supported implementation of an unvalidated integration path; onboarding did not reach a live Ring API “hello world” because there was no authorized simulator/test device available.
- **Build again?** Yes, if test-device or simulator access is available early enough to validate the required runtime flow.

## AWS CLI, IAM Identity Center, and SAM

- **Used for:** Configured AWS CLI IAM Identity Center sign-in, checked the resulting AWS identity availability, validated the SAM template, and built the Python 3.12 ARM64 Lambda packages in Docker.
- **What worked:** SAM lint and the containerized ARM64 package build completed locally. Docker initially failed to start; after it became available, the build succeeded.
- **What needs work:** The browser sign-in authenticated the user, but the Identity Center account instance returned “No AWS accounts are available to you.” That prevented obtaining AWS service credentials and deploying. This project therefore has no live AWS integration evidence.
- **Onboarding:** Local SAM validation/build worked after installing AWS CLI, SAM CLI, and Python 3.12 and starting Docker. No AWS account role was available for deployment.
- **Build again?** Yes for local infrastructure validation; deploy only after an AWS account role and cost controls are available.

## Local prototype tools

- **Used for:** FastAPI/Uvicorn for the local event workflow; Streamlit for reception review; SQLite for local persistence; OpenCV/EasyOCR and optional YOLO weights for image processing; synthetic image generation for the device-free demo.
- **What worked:** The prototype can be demonstrated without cloud credentials or Ring hardware. Generating synthetic sample data avoids putting personal identity documents into a public demo.
- **What needs work:** Synthetic local events do not test Ring APIs, Ring devices, or simulator behavior. OCR quality and end-to-end behavior should be evaluated only with synthetic or properly authorized test data.
- **Onboarding:** The local path is the most accessible demo route; follow the root README and run the API and dashboard separately.
- **Build again?** Yes for prototyping and demos, while keeping it clearly labeled as a prototype.

## Submission scope

The saved hackathon rules require Ring-track entries to use Ring APIs, an SDK, a simulator, or a device at runtime and to demonstrate the project through a simulator or device. The current local synthetic demo does not demonstrate that requirement. Product feedback is a submission requirement; friction notes are maintained in [FRICTION_LOG.md](./FRICTION_LOG.md). Do not claim AWS Builder eligibility unless the required AWS integration or qualifying Kiro Crew use was actually part of the project.
