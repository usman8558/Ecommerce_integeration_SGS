import base64
import functools
import hashlib
import hmac
import requests
import json
import frappe
from frappe import _
from shopify.resources import Webhook
from shopify.session import Session

from ecommerce_integrations.shopify.constants import (
    API_VERSION,
    EVENT_MAPPER,
    SETTING_DOCTYPE,
    WEBHOOK_EVENTS,
)
from ecommerce_integrations.shopify.utils import create_shopify_log

def get_dynamic_access_token(setting):
    return setting.get_password("password")

def get_oauth_token(setting):
    return setting.get_password("password")

def temp_shopify_session(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if frappe.flags.in_test:
            return func(*args, **kwargs)

        setting = frappe.get_doc(SETTING_DOCTYPE)
        if setting.is_enabled():
            token = setting.get_password("password")
            auth_details = (setting.shopify_url, API_VERSION, token)

            with Session.temp(*auth_details):
                return func(*args, **kwargs)

    return wrapper

def register_webhooks(shopify_url: str, password: str) -> list[Webhook]:
    new_webhooks = []
    setting = frappe.get_doc("Shopify Setting")
    permanent_token = setting.get_password("password")

    unregister_webhooks(shopify_url, permanent_token)

    with Session.temp(shopify_url, API_VERSION, permanent_token):
        for topic in WEBHOOK_EVENTS:
            webhook = Webhook.create({"topic": topic, "address": get_callback_url(), "format": "json"})

            if webhook.is_valid():
                new_webhooks.append(webhook)
            else:
                create_shopify_log(
                    status="Error",
                    response_data=webhook.to_dict(),
                    exception=webhook.errors.full_messages(),
                )

    return new_webhooks

def unregister_webhooks(shopify_url: str, password: str) -> None:
    url = get_current_domain_name()
    setting = frappe.get_doc("Shopify Setting")
    permanent_token = setting.get_password("password")

    with Session.temp(shopify_url, API_VERSION, permanent_token):
        for webhook in Webhook.find():
            if url in webhook.address:
                webhook.destroy()

def get_current_domain_name() -> str:
    if frappe.conf.developer_mode and frappe.conf.localtunnel_url:
        return frappe.conf.localtunnel_url
    else:
        return frappe.request.host

def get_callback_url() -> str:
    url = get_current_domain_name()
    return f"https://{url}/api/method/ecommerce_integrations.shopify.connection.store_request_data"

@frappe.whitelist(allow_guest=True)
def store_request_data() -> None:
    if frappe.request:
        hmac_header = frappe.get_request_header("X-Shopify-Hmac-Sha256")
        _validate_request(frappe.request, hmac_header)
        data = json.loads(frappe.request.data)
        event = frappe.request.headers.get("X-Shopify-Topic")
        process_request(data, event)

def process_request(data, event):
    log = create_shopify_log(method=EVENT_MAPPER[event], request_data=data)
    frappe.enqueue(
        method=EVENT_MAPPER[event],
        queue="short",
        timeout=300,
        is_async=True,
        **{"payload": data, "request_id": log.name},
    )

def _validate_request(req, hmac_header):
    import json
    import base64
    import hashlib
    import hmac
    settings = frappe.get_doc("Shopify Setting")

    secret_key = settings.shared_secret

    if not secret_key:
        frappe.throw("Shopify Secret Key is missing in settings")

    secret_key = secret_key.strip()
    raw_data = req.get_data()

    calculated_sig = base64.b64encode(hmac.new(secret_key.encode("utf8"), raw_data, hashlib.sha256).digest()).decode('utf-8')

    if calculated_sig != hmac_header:
        error_msg = f"Signature Mismatch! Shopify sent: {hmac_header} | ERPNext calculated: {calculated_sig}"
        create_shopify_log(status="Error", request_data=json.loads(raw_data), message=error_msg)
        frappe.throw("Unverified Webhook Data")


def auto_refresh_shopify_token():
    try:
        settings = frappe.get_doc("Shopify Setting")
        
        if not settings.is_enabled():
            return
            
        client_id = settings.get("client_id")
        client_secret = settings.shared_secret
        
        if not client_id or not client_secret:
            frappe.log_error("Auto Refresh Failed: Client ID or Shared Secret is missing.", "Shopify Auto Token")
            return
            
        url = f"https://{settings.shopify_url}/admin/oauth/access_token"
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        
        res = requests.post(url, json=payload)
        
        if res.status_code == 200:
            new_token = res.json().get("access_token")
            
            settings.db_set("password", new_token)
            frappe.db.commit()
            
            frappe.cache().delete_value("shopify_oauth_token")
            
            frappe.log_error(f"Token successfully refreshed automatically.", "Shopify Auto Token - Success")
        else:
            frappe.log_error(f"Failed to fetch new token. Error: {res.text}", "Shopify Auto Token")
            
    except Exception as e:
        frappe.log_error(f"Exception in auto token refresh: {str(e)}", "Shopify Auto Token")