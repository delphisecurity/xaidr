"""Shared-tenant apexes: registrable domains whose hosts are not one party's.

A destination is keyed by its registrable domain (the PSL algorithm), so a host
the principal names authorizes its siblings too: ``docs.northbank.example`` and
``billing.northbank.example`` are one owner's. Under the apexes below that is not
so. Their hosts serve content, endpoints or tenants that parties other than the
apex's owner control (``docs.google.com`` and ``script.google.com``,
``acme.slack.com`` and ``hooks.slack.com``), and the Public Suffix List does not
split them into separate registrable domains. A host under one of them is keyed
by the whole host, and a host the principal names authorizes that host and its
subdomains only.

Apexes the PSL already splits need no entry here: every ``<user>.github.io``,
``<bucket>.s3.amazonaws.com``, ``storage.googleapis.com``,
``<account>.blob.core.windows.net``, ``<app>.herokuapp.com`` and the like is its
own registrable domain in the vendored PSL (``_psl_data.py``, private section).

The list is xaidr's own, chosen by that criterion; the test that pins it also
checks that the PSL splits none of these apexes (an entry the PSL splits is dead).
Refreshing it is a core change, like the PSL snapshot.
"""

SHARED_TENANT_SNAPSHOT_DATE = "2026-10-22"

#: Multi-service apexes whose hosts carry other parties' content or endpoints.
_SERVICES = (
    "google.com", "googleusercontent.com",
    "microsoft.com", "office.com", "live.com", "sharepoint.com",
    "amazonaws.com", "azure.net", "oraclecloud.com", "aliyuncs.com", "myqcloud.com",
    "cloudflarestorage.com", "backblazeb2.com", "wasabisys.com",
    "dropbox.com", "dropboxusercontent.com", "box.com", "icloud.com", "github.com",
)

#: Publishing and hosting platforms with a subdomain per user.
_PUBLISHING = (
    "wordpress.com", "medium.com", "substack.com", "tumblr.com", "weebly.com",
    "squarespace.com", "neocities.org", "glitch.me", "railway.app", "loca.lt",
    "statuspage.io",
)

#: Software-as-a-service apexes with a subdomain per customer tenant.
_TENANTS = (
    "slack.com", "atlassian.net", "zendesk.com", "salesforce.com", "force.com",
    "okta.com", "auth0.com", "typeform.com", "freshdesk.com", "service-now.com",
    "notion.so", "hubspot.com", "discord.com", "mailchimp.com",
)

SHARED_TENANT_APEXES = frozenset(_SERVICES + _PUBLISHING + _TENANTS)
