"""
The Vault - Frontend Application
A secure, zero-knowledge secret sharing UI built with Streamlit.
"""

import html
import os
import time
import base64
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx
import streamlit as st

API_BASE_URL = os.getenv("VAULT_API_URL", "http://localhost:8000")
FRONTEND_BASE_URL = os.getenv("VAULT_FRONTEND_URL", "http://localhost:8501")
SELF_DESTRUCT_GIF_PATH = Path(__file__).with_name("selfish-quotes.gif")
DEFAULT_SELF_DESTRUCT_SECONDS = int(os.getenv("VAULT_SELF_DESTRUCT_SECONDS", "12"))

CUSTOM_CSS = """
<style>
    /* Global styling */
    .stApp { max-width: 900px; margin: 0 auto; }
    .stTextArea textarea { font-family: 'Consolas', 'Monaco', monospace; }
    
    /* Link container styling */
    .link-container {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 2px solid #0f3460;
        border-radius: 12px;
        padding: 24px;
        margin: 20px 0;
        text-align: center;
    }
    .link-container h4 {
        color: #e94560;
        margin-bottom: 16px;
    }
    .link-box {
        background: #0a0a0a;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 16px;
        font-family: 'Consolas', monospace;
        font-size: 13px;
        word-break: break-all;
        color: #00d9ff;
        margin: 12px 0;
    }
    
    /* Secret display styling */
    .secret-revealed {
        background: linear-gradient(135deg, #1a472a 0%, #0d2818 100%);
        border: 2px solid #2ecc71;
        border-radius: 12px;
        padding: 24px;
        margin: 20px 0;
    }
    .secret-content {
        background: #0a0a0a;
        border: 1px solid #2ecc71;
        border-radius: 8px;
        padding: 20px;
        font-family: 'Consolas', monospace;
        font-size: 14px;
        white-space: pre-wrap;
        word-break: break-word;
        color: #fff;
        max-height: 400px;
        overflow-y: auto;
    }
    .secret-content.no-copy {
        user-select: none;
        -webkit-user-select: none;
        -moz-user-select: none;
        -ms-user-select: none;
    }
    
    /* Status indicators */
    .status-online { color: #2ecc71; font-weight: bold; }
    .status-offline { color: #e74c3c; font-weight: bold; }
    
    /* Info cards */
    .info-card {
        background: #1a1a2e;
        border-radius: 10px;
        padding: 16px;
        margin: 10px 0;
        border-left: 4px solid #3498db;
    }
    
    /* Button improvements */
    .stButton > button {
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 12px 24px;
        border-radius: 8px 8px 0 0;
    }
</style>
"""


@st.cache_data(ttl=30)
def get_api_health() -> Optional[dict]:
    """Check API health status with caching."""
    try:
        response = httpx.get(f"{API_BASE_URL}/health", timeout=3)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError:
        return None


def check_secret_exists(secret_id: str) -> Optional[dict]:
    """Check if a secret exists and its metadata."""
    if not secret_id or len(secret_id) < 10:
        return None
    try:
        response = httpx.get(f"{API_BASE_URL}/check/{secret_id}", timeout=5)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError:
        return None


def post_generate_secret(text: str, ttl_minutes: int, password: Optional[str] = None, copy_enabled: bool = True) -> dict:
    """Generate a new secret via API."""
    payload = {"text": text, "ttl_minutes": ttl_minutes, "copy_enabled": copy_enabled}
    if password:
        payload["password"] = password
    response = httpx.post(f"{API_BASE_URL}/generate", json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def post_retrieve_secret(secret_id: str, key: str, password: Optional[str] = None) -> dict:
    """Retrieve a secret via API."""
    payload = {"key": key}
    if password:
        payload["password"] = password
    response = httpx.post(f"{API_BASE_URL}/retrieve/{secret_id}", json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def build_share_link(secret_id: str, key: str, self_destruct_seconds: Optional[int] = None) -> str:
    """Build a shareable URL for the secret."""
    params: dict[str, str] = {"uuid": secret_id, "key": key}
    if self_destruct_seconds is not None:
        params["sd"] = str(int(self_destruct_seconds))
    query = urlencode(params)
    return f"{FRONTEND_BASE_URL}?{query}"


def display_secret_content(decrypted_message: str, allow_copy: bool = True) -> None:
    """Display the decrypted secret content with optional copy restriction."""
    safe_message = html.escape(decrypted_message)
    copy_class = "" if allow_copy else " no-copy"
    
    if not allow_copy:
        st.warning("🔒 **Message copying is disabled** - This message cannot be copied or selected.")
    
    st.markdown(
        f"""
        <div class="secret-revealed">
            <div class="secret-content{copy_class}">{safe_message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def run_self_destruct_sequence(decrypted_message: str, seconds: int, allow_copy: bool = True) -> None:
    seconds = max(3, int(seconds))

    safe_message = html.escape(decrypted_message)
    copy_class = "" if allow_copy else " no-copy"

    banner = st.empty()
    body = st.empty()

    if not allow_copy:
        body.warning("🔒 **Message copying is disabled** - This message cannot be copied or selected.")
    
    body.markdown(
        f"""
        <div class="secret-revealed">
            <div class="secret-content{copy_class}">{safe_message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    for remaining in range(seconds, 0, -1):
        banner.markdown(
            f"""
            <div class="link-container">
                <h4>⏳ Messege self-destructs in: {remaining}s</h4>
                <div style="color:#c7d2fe; font-size: 13px;">This view will auto-clear locally.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        time.sleep(1)

    banner.empty()
    body.empty()
    
    if SELF_DESTRUCT_GIF_PATH.exists():
        st.markdown(
            """
            <div style="display: flex; justify-content: center; align-items: center;">
            """,
            unsafe_allow_html=True,
        )
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.image(str(SELF_DESTRUCT_GIF_PATH), use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.success("✅ Display cleared. Server copy was already destroyed after retrieval.")


def render_header() -> None:
    """Render the app header with status indicator."""
    col1, col2 = st.columns([5, 1])
    with col1:
        st.markdown("# 🗝️ The Vault")
        st.markdown("*Zero-knowledge, self-destructing secret sharing*")
    with col2:
        health = get_api_health()
        if health:
            st.markdown("**Status**")
            st.markdown('<span class="status-online">● Online</span>', unsafe_allow_html=True)
        else:
            st.markdown("**Status**")
            st.markdown('<span class="status-offline">● Offline</span>', unsafe_allow_html=True)
    
    st.markdown("---")


def render_create_tab() -> None:
    """Render the Create Secret tab."""
    st.markdown("### 📝 Create a One-Time Secret")
    st.markdown("Your secret will be encrypted client-side. The decryption key is **never stored** on our servers.")
    
    st.markdown("")
    
    secret_text = st.text_area(
        "Enter your secret message",
        placeholder="Paste your sensitive data here...\n\nExamples:\n• Passwords\n• API keys\n• Private messages\n• Configuration secrets",
        height=180,
        key="secret_input",
    )

    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        ttl_options = {
            "5 minutes": 5,
            "15 minutes": 15,
            "1 hour": 60,
            "6 hours": 360,
            "24 hours": 1440,
        }
        ttl_label = st.selectbox(
            "🔗 Expires in",
            options=list(ttl_options.keys()),
            index=2,
        )
        ttl_minutes = ttl_options[ttl_label]
    
    with col2:
        use_password = st.checkbox("🔒 Add password protection", value=False)
        password = None
        if use_password:
            password = st.text_input(
                "Set password",
                type="password",
                placeholder="Enter password",
                label_visibility="collapsed",
            )

    st.markdown("")
    enable_copy = st.checkbox("📋 Enable Message Copy", value=True, help="If checked, recipients can copy the message. If unchecked, the message cannot be selected or copied.")

    with col3:
        self_destruct_seconds = st.number_input(
            "⏲️ Timer to self-destruct",
            min_value=3,
            max_value=60,
            value=DEFAULT_SELF_DESTRUCT_SECONDS,
            step=1,
            help="This sets the countdown to view the messege before clearing it on display. Does not change backend TTL.",
        )

    st.markdown("")
    
    generate_clicked = st.button(
        "🔐 Generate Secure Link",
        type="primary",
        use_container_width=True,
        disabled=not secret_text.strip(),
    )

    if generate_clicked:
        if not secret_text.strip():
            st.error("❌ Please enter some secret text.")
        elif use_password and not password:
            st.error("❌ Please enter a password or disable password protection.")
        else:
            with st.status("🔄 Creating your secure secret...", expanded=True) as status:
                st.write("Generating encryption key...")
                st.write("Encrypting your secret...")
                
                try:
                    data = post_generate_secret(secret_text, ttl_minutes, password, enable_copy)
                    st.write("Storing encrypted data...")
                    status.update(label="✅ Secret created successfully!", state="complete")
                except httpx.HTTPError as exc:
                    status.update(label="❌ Failed to create secret", state="error")
                    st.error(f"Error: {exc}")
                    return

            share_link = build_share_link(data["uuid"], data["key"], int(self_destruct_seconds))
            
            st.markdown("")
            st.markdown("---")
            st.markdown("### 🎉 Your Secret Link is Ready!")
            
            st.markdown(
                f"""
                <div class="link-container">
                    <h4>🔗 Share this link (one-time use only)</h4>
                    <div class="link-box">{share_link}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.code(share_link, language=None)
            
            st.markdown("")
            
            info_col1, info_col2, info_col3 = st.columns(3)
            with info_col1:
                st.metric("⏱️ Expires In", ttl_label)
            with info_col2:
                st.metric("🔒 Password", "Yes" if data["password_protected"] else "No")
            with info_col3:
                st.metric("👁️ Views", "1 max")
            
            st.markdown("")
            
            st.info(
                "**📋 How to share:**\n"
                "1. Copy the link above\n"
                "2. Send it to your recipient via any channel\n"
                "3. They click the link and see the secret\n"
                "4. The secret is **permanently deleted** after viewing"
            )
            
            if data["password_protected"]:
                st.warning(
                    "**🔐 Password Required:**\n"
                    "Remember to share the password **separately** from the link for maximum security!"
                )


def render_view_tab(has_secret_in_url: bool) -> None:
    """Render the View Secret tab."""
    params = st.query_params
    prefill_uuid = params.get("uuid", "")
    prefill_key = params.get("key", "")
    prefill_self_destruct = params.get("sd", "")
    
    if has_secret_in_url:
        st.markdown("### 🔓 You've Received a Secret!")
        st.markdown("Someone has shared a secure, one-time secret with you.")
        st.markdown("")
        
        st.info(
            "**⚠️ Important:** This secret can only be viewed **once**. "
            "After you click 'Reveal Secret', it will be permanently destroyed."
        )
        
        needs_password = False
        check_result = check_secret_exists(prefill_uuid)
        
        if check_result is None or not check_result.get("exists"):
            st.error(
                "**❌ Secret Not Found**\n\n"
                "This secret may have:\n"
                "- Already been viewed and destroyed\n"
                "- Expired due to time limit\n"
                "- Never existed"
            )
            if st.button("🏠 Create a New Secret", type="primary"):
                st.query_params.clear()
                st.rerun()
            return
        
        if check_result.get("password_protected"):
            needs_password = True
            st.warning("🔒 This secret is **password-protected**. You'll need the password to view it.")
        
        try:
            self_destruct_seconds = int(prefill_self_destruct) if prefill_self_destruct else DEFAULT_SELF_DESTRUCT_SECONDS
        except ValueError:
            self_destruct_seconds = DEFAULT_SELF_DESTRUCT_SECONDS

        password = None
        if needs_password:
            password = st.text_input(
                "Enter Password",
                type="password",
                placeholder="Enter the password shared with you",
            )
        
        st.markdown("")
        
        col1, col2 = st.columns(2)
        with col1:
            reveal_clicked = st.button(
                "👁️ Reveal Secret",
                type="primary",
                use_container_width=True,
                disabled=(needs_password and not password),
            )
        with col2:
            if st.button("❌ Cancel", use_container_width=True):
                st.query_params.clear()
                st.rerun()
        
        if reveal_clicked:
            with st.status("🔄 Decrypting secret...", expanded=True) as status:
                st.write("Fetching encrypted data...")
                st.write("Decrypting with your key...")
                
                try:
                    payload = post_retrieve_secret(prefill_uuid, prefill_key, password)
                    st.write("Destroying server copy...")
                    status.update(label="✅ Secret decrypted!", state="complete")
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        status.update(label="❌ Secret not found", state="error")
                        st.error("This secret has already been viewed or has expired.")
                    elif exc.response.status_code == 401:
                        status.update(label="❌ Authentication failed", state="error")
                        st.error("Incorrect password. Please try again.")
                        return
                    elif exc.response.status_code == 400:
                        status.update(label="❌ Decryption failed", state="error")
                        st.error("Invalid decryption key.")
                    else:
                        status.update(label="❌ Error", state="error")
                        st.error(f"Unexpected error: {exc}")
                    return
                except httpx.HTTPError as exc:
                    status.update(label="❌ Connection error", state="error")
                    st.error(f"Failed to reach the server: {exc}")
                    return

            st.markdown("")
            st.markdown("---")
            st.markdown("### 🔓 Decrypted Secret")
            st.warning(
                "**⚠️ One-time reveal**\n\n"
                "The server copy is destroyed immediately after retrieval. This UI will now start a self-destruct countdown."
            )

            allow_copy = payload.get("copy_enabled", True)
            run_self_destruct_sequence(payload["decrypted_message"], self_destruct_seconds, allow_copy)
            st.query_params.clear()

            st.markdown("")
            if st.button("🏠 Create Your Own Secret", type="primary"):
                st.rerun()
    
    else:
        st.markdown("### 👁️ View a Secret")
        st.markdown("Enter the secret details manually if you have them.")
        
        st.markdown("")
        
        manual_uuid = st.text_input(
            "Secret UUID",
            placeholder="e.g., 550e8400-e29b-41d4-a716-446655440000",
        )
        manual_key = st.text_input(
            "Decryption Key",
            type="password",
            placeholder="The key from your secret link",
        )
        
        needs_password = False
        if manual_uuid and len(manual_uuid) > 10:
            check_result = check_secret_exists(manual_uuid)
            if check_result and check_result.get("exists"):
                st.success("✅ Secret found!")
                if check_result.get("password_protected"):
                    needs_password = True
                    st.warning("🔒 This secret requires a password.")
            elif check_result and not check_result.get("exists"):
                st.error("❌ Secret not found or already destroyed.")
        
        password = None
        if needs_password:
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter password",
                key="manual_password",
            )
        
        if st.button(
            "👁️ Reveal Secret",
            type="primary",
            use_container_width=True,
            disabled=not (manual_uuid and manual_key),
        ):
            if not manual_uuid or not manual_key:
                st.error("Both UUID and key are required.")
            elif needs_password and not password:
                st.error("Password is required for this secret.")
            else:
                with st.status("🔄 Decrypting...", expanded=True) as status:
                    try:
                        payload = post_retrieve_secret(manual_uuid, manual_key, password)
                        status.update(label="✅ Success!", state="complete")
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            status.update(label="❌ Not found", state="error")
                            st.error("Secret not found or already destroyed.")
                        elif exc.response.status_code == 401:
                            status.update(label="❌ Auth failed", state="error")
                            st.error("Incorrect password.")
                        else:
                            status.update(label="❌ Error", state="error")
                            st.error(f"Error: {exc}")
                        return
                    except httpx.HTTPError as exc:
                        status.update(label="❌ Error", state="error")
                        st.error(f"Connection error: {exc}")
                        return
                
                st.markdown("---")
                st.markdown("### 🔓 Decrypted Secret")
                st.warning("⚠️ This secret has been permanently destroyed on the server. Starting UI self-destruct timer now.")
                allow_copy = payload.get("copy_enabled", True)
                run_self_destruct_sequence(payload["decrypted_message"], DEFAULT_SELF_DESTRUCT_SECONDS, allow_copy)


def render_about_tab() -> None:
    """Render the About tab."""
    st.markdown("### ℹ️ How The Vault Works")
    
    st.markdown("""
    **The Vault** implements a zero-knowledge security model, meaning we **cannot** read your secrets even if we wanted to.
    """)
    
    st.markdown("#### 🔐 The Security Model")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **What We Store:**
        - Encrypted blob (unreadable)
        - Expiration timestamp
        - Password hash (optional)
        
        **What We DON'T Store:**
        - Your original message
        - The encryption key
        - Any way to decrypt
        """)
    
    with col2:
        st.markdown("""
        **Security Features:**
        - 🔒 AES-128 encryption (Fernet)
        - 🔥 One-time read (burn after reading)
        - ⏱️ Auto-expiration
        - 🔑 Optional password protection
        - 🚫 No server-side decryption capability
        """)
    
    st.markdown("---")
    
    st.markdown("#### 📋 Step-by-Step Flow")
    
    st.markdown("""
    1. **You create a secret** → We generate a unique encryption key
    2. **We encrypt your text** → Using the key (AES-128 + HMAC)
    3. **We store ONLY the encrypted blob** → Key goes in your link
    4. **You share the link** → Contains UUID + decryption key
    5. **Recipient clicks link** → Provides the key back to us
    6. **We decrypt and DELETE** → Secret is gone forever
    """)
    
    st.markdown("---")
    
    st.markdown("#### 🛡️ Best Practices")
    
    st.info("""
    - **Use password protection** for highly sensitive data
    - **Share passwords separately** from links (different channel)
    - **Set short expiration times** when possible
    - **Verify receipt** with the recipient
    """)


def main() -> None:
    """Main application entry point."""
    st.set_page_config(
        page_title="The Vault - Secure Secret Sharing",
        page_icon="🗝️",
        layout="centered",
        initial_sidebar_state="collapsed",
    )
    
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    
    params = st.query_params
    has_secret_in_url = bool(params.get("uuid") and params.get("key"))
    
    render_header()
    
    if has_secret_in_url:
        tab_names = ["👁️ View Secret", "📝 Create Secret", "ℹ️ About"]
        view_tab, create_tab, about_tab = st.tabs(tab_names)
        
        with view_tab:
            render_view_tab(has_secret_in_url=True)
        with create_tab:
            render_create_tab()
        with about_tab:
            render_about_tab()
    else:
        tab_names = ["📝 Create Secret", "👁️ View Secret", "ℹ️ About"]
        create_tab, view_tab, about_tab = st.tabs(tab_names)
        
        with create_tab:
            render_create_tab()
        with view_tab:
            render_view_tab(has_secret_in_url=False)
        with about_tab:
            render_about_tab()
    
    st.markdown("---")
    st.markdown(
        "<center><small>🔒 Built with security in mind</small></center>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
