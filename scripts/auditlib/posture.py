from __future__ import annotations

from typing import Any


def vpn_posture(data: dict[str, Any]) -> dict[str, Any]:
    raw=data.get("vpn")
    if not isinstance(raw,dict):return {"status":"unavailable","servers":[],"site_to_site":[],"remote_management_path":"unknown","summary":"VPN dataset unavailable."}
    servers=[{"name":str(x.get("name") or "unnamed"),"type":str(x.get("type") or "unknown"),"enabled":x.get("enabled") if "enabled" in x else None} for x in raw.get("servers") or [] if isinstance(x,dict)]
    tunnels=[{"name":str(x.get("name") or "unnamed"),"type":str(x.get("type") or "unknown")} for x in raw.get("site_to_site") or [] if isinstance(x,dict)]
    enabled=[x for x in servers if x["enabled"] is True]
    path="plausible" if enabled else "not established" if servers else "unknown"
    summary=(f"{len(servers)} VPN server(s) and {len(tunnels)} site-to-site tunnel(s) collected; " + (f"{len(enabled)} enabled server(s) provide a plausible remote-access path." if enabled else "no enabled remote-access server was established from collected evidence."))
    return {"status":"collected and analyzed","servers":servers,"site_to_site":tunnels,"remote_management_path":path,"summary":summary,"caution":"Configuration does not prove reachability, authentication quality, or authorization to protected resources."}


def ids_ips_posture(data: dict[str, Any]) -> dict[str, Any]:
    raw=data.get("ids_ips")
    if raw is None:return {"status":"unavailable","enabled":"unknown","mode":"unknown","summary":"IDS/IPS settings unavailable."}
    settings=next((x for x in raw if isinstance(x,dict)),None) if isinstance(raw,list) else raw if isinstance(raw,dict) else None
    if not settings:return {"status":"collected, empty","enabled":"unknown","mode":"unknown","summary":"IDS/IPS dataset was collected but empty."}
    mode=str(settings.get("ips_mode") or "unknown"); enabled="enabled" if mode.lower() not in {"unknown","disabled","off","none"} else "disabled" if mode.lower() in {"disabled","off","none"} else "unknown"
    material={k:settings.get(k) for k in ("advanced_filtering_preference","memory_optimized","honeypot_enabled") if k in settings}
    if isinstance(settings.get("enabled_categories"),list): material["enabled_categories_count"]=len(settings["enabled_categories"])
    return {"status":"collected and analyzed","enabled":enabled,"mode":mode,"material_settings":material,"summary":f"Threat management configuration reports mode {mode!r} ({enabled}).","caution":"Configured posture does not prove detection or prevention effectiveness."}


def _pf_signature(x):
    return tuple(str(x.get(k) or "") for k in ("_id","name","fwd","fwd_port","dst_port","proto"))


def upnp_posture(data: dict[str, Any]) -> dict[str, Any]:
    raw=data.get("upnp_exposure"); status=(data.get("collection_status") or {}).get("upnp_exposure",{}).get("status")
    if raw is None:return {"status":"unsupported" if status=="unavailable" else "unavailable","runtime_entries_observed":0,"summary":"UPnP/forwarding evidence was unavailable."}
    if not raw:return {"status":"collected, empty","runtime_entries_observed":0,"summary":"UPnP/forwarding dataset was collected and empty."}
    configured={_pf_signature(x) for x in data.get("port_forwards") or [] if isinstance(x,dict)}
    extra=[x for x in raw if isinstance(x,dict) and _pf_signature(x) not in configured]
    return {"status":"collected and analyzed","collected_entries":len(raw),"configured_forward_matches":len(raw)-len(extra),"runtime_entries_observed":len(extra),"summary":f"Collected {len(raw)} forwarding-status entries; {len(extra)} distinct entry/entries were not matched to configured port forwards.","caution":"An unmatched entry is a dynamic-exposure candidate, not proof that UPnP created it."}
