import os
import time
from pathlib import Path
from typing import Any

import boto3
import httpx
import streamlit as st
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

st.set_page_config(page_title="DeskPass | Reception", layout="wide")
st.title("DeskPass | Reception")
st.caption("Ring events and receptionist review. This dashboard does not control a physical lock.")

api_url = st.sidebar.text_input(
    "Deployable API URL",
    value=os.environ.get("DESKPASS_API_URL", "").rstrip("/"),
)
aws_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "")
cognito_client_id = os.environ.get("DESKPASS_COGNITO_CLIENT_ID", "")


def _cognito_client() -> Any:
    if not aws_region or not cognito_client_id:
        raise RuntimeError(
            "Set AWS_REGION and DESKPASS_COGNITO_CLIENT_ID in deployable/.env."
        )
    return boto3.client("cognito-idp", region_name=aws_region)


def _save_auth_response(
    response: dict[str, Any],
    username: str,
    refresh_token: str | None = None,
) -> bool:
    result = response.get("AuthenticationResult")
    if isinstance(result, dict) and isinstance(result.get("IdToken"), str):
        st.session_state["cognito_auth"] = {
            "id_token": result["IdToken"],
            "access_token": result.get("AccessToken", ""),
            "refresh_token": result.get("RefreshToken") or refresh_token,
            "expires_at": time.time() + int(result.get("ExpiresIn", 900)),
            "username": username,
        }
        st.session_state.pop("cognito_challenge", None)
        return True

    challenge_name = response.get("ChallengeName")
    session = response.get("Session")
    if not isinstance(challenge_name, str) or not isinstance(session, str):
        st.error("Cognito did not return a usable sign-in result.")
        st.session_state.pop("cognito_challenge", None)
        return False

    challenge: dict[str, Any] = {
        "name": challenge_name,
        "session": session,
        "username": username,
    }
    if challenge_name == "MFA_SETUP":
        association = _cognito_client().associate_software_token(Session=session)
        challenge["session"] = association.get("Session", session)
        challenge["secret_code"] = association["SecretCode"]
    st.session_state["cognito_challenge"] = challenge
    return False


def _display_cognito_error(error: ClientError) -> None:
    code = error.response.get("Error", {}).get("Code", "UnknownError")
    if code in {
        "CodeMismatchException",
        "ExpiredCodeException",
        "NotAuthorizedException",
        "UserNotFoundException",
    }:
        st.error("Sign-in was not accepted. Check the credentials or authenticator code and try again.")
    else:
        st.error(f"Cognito sign-in failed ({code}). Contact the site administrator if it continues.")


def _finish_challenge(response: dict[str, Any], challenge: dict[str, Any]) -> None:
    try:
        authenticated = _save_auth_response(
            response,
            challenge["username"],
            st.session_state.get("cognito_auth", {}).get("refresh_token"),
        )
        if authenticated or isinstance(st.session_state.get("cognito_challenge"), dict):
            st.rerun()
    except ClientError as error:
        _display_cognito_error(error)


def _render_sign_in() -> None:
    if not aws_region or not cognito_client_id:
        st.error("Set AWS_REGION and DESKPASS_COGNITO_CLIENT_ID in deployable/.env.")
        st.stop()
    challenge = st.session_state.get("cognito_challenge")
    if challenge is None:
        with st.form("cognito-login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            st.session_state["clear_login_password"] = True
            try:
                response = _cognito_client().initiate_auth(
                    AuthFlow="USER_PASSWORD_AUTH",
                    ClientId=cognito_client_id,
                    AuthParameters={"USERNAME": username.strip(), "PASSWORD": password},
                )
                authenticated = _save_auth_response(response, username.strip())
                if authenticated or isinstance(
                    st.session_state.get("cognito_challenge"), dict
                ):
                    st.rerun()
            except ClientError as error:
                _display_cognito_error(error)
            except RuntimeError as error:
                st.error(str(error))
        st.stop()

    challenge_name = challenge["name"]
    if challenge_name == "MFA_SETUP":
        st.info("Set up an authenticator app to continue. This site requires multi-factor authentication.")
        st.code(challenge["secret_code"])
        st.caption("Add the key above to an authenticator app, then enter its current six-digit code.")
        with st.form("mfa-setup"):
            code = st.text_input("Authenticator code", key="mfa_setup_code")
            submitted = st.form_submit_button("Verify authenticator")
        if submitted:
            st.session_state["clear_mfa_code"] = "mfa_setup_code"
            try:
                client = _cognito_client()
                verified = client.verify_software_token(
                    Session=challenge["session"],
                    UserCode=code.strip(),
                    FriendlyDeviceName="DeskPass Reception",
                )
                response = client.respond_to_auth_challenge(
                    ClientId=cognito_client_id,
                    ChallengeName="MFA_SETUP",
                    Session=verified.get("Session", challenge["session"]),
                    ChallengeResponses={
                        "USERNAME": challenge["username"],
                        "MFA_SETUP": "SOFTWARE_TOKEN_MFA",
                    },
                )
                _finish_challenge(response, challenge)
            except ClientError as error:
                _display_cognito_error(error)
    elif challenge_name == "SOFTWARE_TOKEN_MFA":
        with st.form("mfa-login"):
            code = st.text_input("Authenticator code", key="mfa_login_code")
            submitted = st.form_submit_button("Verify code", type="primary")
        if submitted:
            st.session_state["clear_mfa_code"] = "mfa_login_code"
            try:
                response = _cognito_client().respond_to_auth_challenge(
                    ClientId=cognito_client_id,
                    ChallengeName=challenge_name,
                    Session=challenge["session"],
                    ChallengeResponses={
                        "USERNAME": challenge["username"],
                        "SOFTWARE_TOKEN_MFA_CODE": code.strip(),
                    },
                )
                _finish_challenge(response, challenge)
            except ClientError as error:
                _display_cognito_error(error)
    elif challenge_name == "NEW_PASSWORD_REQUIRED":
        with st.form("new-password"):
            password = st.text_input("New password", type="password", key="new_password")
            confirmation = st.text_input("Confirm new password", type="password")
            submitted = st.form_submit_button("Set password", type="primary")
        if submitted:
            st.session_state["clear_login_password"] = True
            st.session_state["clear_new_password"] = True
            if len(password) < 14 or password != confirmation:
                st.error("Passwords must match and be at least 14 characters.")
            else:
                try:
                    response = _cognito_client().respond_to_auth_challenge(
                        ClientId=cognito_client_id,
                        ChallengeName=challenge_name,
                        Session=challenge["session"],
                        ChallengeResponses={
                            "USERNAME": challenge["username"],
                            "NEW_PASSWORD": password,
                        },
                    )
                    _finish_challenge(response, challenge)
                except ClientError as error:
                    _display_cognito_error(error)
            st.rerun()
    else:
        st.error(f"Unsupported Cognito sign-in challenge: {challenge_name}")
        if st.button("Restart sign-in"):
            st.session_state.pop("cognito_challenge", None)
            st.rerun()
        st.stop()

    st.stop()


if st.session_state.pop("clear_login_password", False):
    st.session_state.pop("login_password", None)
if st.session_state.pop("clear_new_password", False):
    st.session_state.pop("new_password", None)
code_to_clear = st.session_state.pop("clear_mfa_code", None)
if isinstance(code_to_clear, str):
    st.session_state.pop(code_to_clear, None)

auth = st.session_state.get("cognito_auth")
if isinstance(auth, dict) and time.time() >= auth.get("expires_at", 0):
    refresh_token = auth.get("refresh_token")
    if refresh_token:
        try:
            refreshed = _cognito_client().initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                ClientId=cognito_client_id,
                AuthParameters={"REFRESH_TOKEN": refresh_token},
            )
            if _save_auth_response(refreshed, auth["username"], refresh_token):
                auth = st.session_state.get("cognito_auth")
            else:
                st.session_state.pop("cognito_auth", None)
                auth = None
        except ClientError as error:
            _display_cognito_error(error)
            st.session_state.pop("cognito_auth", None)
            auth = None
    else:
        st.session_state.pop("cognito_auth", None)
        auth = None

if not isinstance(auth, dict) or not auth.get("id_token"):
    _render_sign_in()

st.sidebar.caption(f"Signed in as {auth['username']}")
if st.sidebar.button("Sign out"):
    try:
        if auth.get("access_token"):
            _cognito_client().global_sign_out(AccessToken=auth["access_token"])
    except ClientError as error:
        _display_cognito_error(error)
    st.session_state.pop("cognito_auth", None)
    st.session_state.pop("cognito_challenge", None)
    st.rerun()


def api_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    if not api_url:
        st.error("Set DESKPASS_API_URL in deployable/.env.")
        st.stop()
    try:
        response = httpx.request(
            method,
            f"{api_url}{path}",
            headers={"Authorization": f"Bearer {auth['id_token']}"},
            timeout=15.0,
            **kwargs,
        )
        if response.status_code == 401:
            st.session_state.pop("cognito_auth", None)
            st.error("Your sign-in expired or is no longer authorized. Sign in again.")
            st.stop()
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        detail = error.response.text[:500]
        st.error(f"DeskPass API returned HTTP {error.response.status_code}: {detail}")
        st.stop()
    except httpx.HTTPError as error:
        st.error(f"Could not reach the DeskPass API ({type(error).__name__}).")
        st.stop()
    return response.json()


if st.button("Refresh events", type="primary"):
    st.rerun()

events = api_request("GET", "/admin/events").get("events", [])
if not events:
    st.info("No Ring events have been received yet.")

for item in events:
    event_id = str(item.get("event_id", ""))
    status = str(item.get("status", "UNKNOWN"))
    with st.expander(f"{status} · {item.get('event_type', 'Ring event')} · {event_id}"):
        st.write(f"Device: {item.get('device_id', 'unknown')}")
        st.write(f"Received: {item.get('created_at', 'unknown')}")
        if item.get("matched_identity") and item["matched_identity"] != "UNKNOWN_VISITOR":
            st.write(f"Possible allowlist match: {item['matched_identity']}")
        if item.get("matched_company") and item["matched_company"] != "UNKNOWN_COMPANY":
            st.write(f"Company: {item['matched_company']}")
        if item.get("match_score") is not None:
            st.write(f"Name match score: {item['match_score']}%")
        if status == "PENDING_REVIEW":
            left, right = st.columns(2)
            if left.button("Approve", key=f"approve-{event_id}"):
                api_request(
                    "POST",
                    f"/admin/events/{event_id}/review",
                    json={"decision": "APPROVED"},
                )
                st.success("Approval recorded.")
                st.rerun()
            if right.button("Deny", key=f"deny-{event_id}"):
                api_request(
                    "POST",
                    f"/admin/events/{event_id}/review",
                    json={"decision": "DENIED"},
                )
                st.success("Denial recorded.")
                st.rerun()
        if st.button("Generate privacy-limited summary", key=f"summary-{event_id}"):
            summary = api_request("POST", f"/admin/events/{event_id}/summary")
            st.info(summary["summary"])
