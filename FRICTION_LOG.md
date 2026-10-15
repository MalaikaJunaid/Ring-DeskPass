# Friction Log

This log records observed development issues and their workarounds. It does not claim a live Ring integration, a production deployment, or a judging bonus. Personal identity document contents and credentials are intentionally excluded.

## Entry 01: Ring runtime access

- **Attempt:** Explore the Ring Partner API and build an event-driven visitor workflow.
- **Friction:** No authorized Ring simulator/test device was available to verify OAuth, event delivery, the production payload, or snapshot retrieval. Playground credentials are not a substitute for a durable, live test.
- **Workaround:** Keep the existing local demo explicitly synthetic, and isolate the unvalidated official-API path in `deployable/`.
- **Remaining:** Obtain approved test access and demonstrate the required runtime flow before claiming Ring-track compliance.

## Entry 02: Local camera and hardware testing

- **Attempt:** Exercise camera capture from the local application.
- **Friction:** Local camera access was unreliable in the development environment.
- **Workaround:** Use an in-memory synthetic badge image for the device-free demo rather than relying on a camera or real identity document.
- **Remaining:** The synthetic flow does not validate Ring devices or the official Ring simulator.

## Entry 03: OCR and sensitive test data

- **Attempt:** Evaluate badge/name extraction with image processing and OCR.
- **Friction:** OCR results on real identity documents were not dependable enough for access decisions, and real IDs must not be included in public artifacts.
- **Workaround:** Use synthetic badges for demos; exclude identity-document images and extracted text from logs and submissions.
- **Remaining:** Validate recognition only with synthetic or properly authorized test data. Any uncertain match must remain a human-review case.

## Entry 04: Cloud service access

- **Attempt:** Prepare the separate AWS-backed path and explore cloud-service integrations.
- **Friction:** The configured IAM Identity Center account instance authenticated the browser session but reported “No AWS accounts are available to you.” No AWS service credentials or deployment role were available.
- **Workaround:** Keep the demo local and do not deploy. Unit tests, SAM lint, and local package builds do not require AWS account access.
- **Remaining:** An administrator must assign an AWS account and deployment role before any AWS deployment can be attempted. No cloud resources were deployed during these checks.

## Entry 05: Containerized Lambda build

- **Attempt:** Build the Python 3.12 ARM64 Lambda packages with SAM.
- **Friction:** Docker Desktop's Linux engine initially did not start, and SAM could not build the containerized package.
- **Workaround:** Start Docker Desktop, verify its Linux engine, and rerun `sam build --use-container`. The Python 3.12 ARM64 build then succeeded locally.
- **Remaining:** This is packaging validation only; it does not validate AWS deployment or Ring behavior.

## Entry 06: Python dependency isolation

- **Attempt:** Check both the prototype and deployable dependency sets.
- **Friction:** The shared development environment contained unrelated packages with conflicting protobuf requirements. A clean check of the shared environment therefore did not prove the deployable dependency set was sound.
- **Workaround:** Create `deployable/.venv` with Python 3.12 and install only `deployable/requirements.txt`.
- **Result:** The isolated deployable environment passed `pip check`; all 12 deployable unit tests passed.

## Entry 07: Submission boundary

- **Attempt:** Assess whether the current no-device prototype demonstrates the Ring track.
- **Friction:** The local synthetic webhook is not an official Ring API, SDK, simulator, or device demonstration.
- **Workaround:** Document the local project as a prototype and keep Ring runtime claims out of its description.
- **Remaining:** The saved hackathon rules require a Ring-runtime demo through an API, SDK, simulator, or device. Recheck the current Devpost rules and complete that demo before claiming Ring-track eligibility.
