from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any

from unifi_common import Finding


@dataclass
class NormalizedPolicy:
    id: str; name: str; enabled: bool; action: str
    source_zone: str; destination_zone: str
    source_scope: dict[str, Any]; destination_scope: dict[str, Any]
    protocol: str; connection_states: list[str]
    index: int; logging: bool; ip_version: str; origin: str
    allow_return_traffic: bool | None
    def as_dict(self): return asdict(self)


def _network_maps(data):
    by_id={}; by_vlan={}
    for n in data.get("networks") or []:
        for key in ("id","_id","external_id"):
            if n.get(key): by_id[str(n[key])]=str(n.get("name") or "unknown")
        explicit=n.get("vlan",n.get("vlan_id"))
        purpose=str(n.get("purpose") or "").lower()
        if explicit is not None and str(explicit).isdigit(): by_vlan[int(explicit)]=n
        elif purpose in {"corporate","lan"} and str(n.get("name") or "").lower()=="default": by_vlan[1]=n
    return by_id,by_vlan


def _items(block):
    return [{"type":str(x.get("type") or "unknown"),"value":str(x.get("value") or "unknown")} for x in (block or {}).get("items") or [] if isinstance(x,dict)]


def _scope(side, network_by_id):
    traffic=(side or {}).get("trafficFilter") or {}; typ=str(traffic.get("type") or "ANY")
    result={"type":typ,"networks":[],"addresses":[],"ports":[],"mac_addresses":[],"applications":[],"match_opposite":False}
    nf=traffic.get("networkFilter") or {}; result["networks"]=[network_by_id.get(str(x),"unresolved") for x in nf.get("networkIds") or []]
    af=traffic.get("ipAddressFilter") or {}; result["addresses"]=_items(af)
    pf=traffic.get("portFilter") or {}; result["ports"]=_items(pf)
    mf=traffic.get("macAddressFilter") or {}; result["mac_addresses"]=[str(x) for x in mf.get("macAddresses") or []]
    app=traffic.get("applicationFilter") or {}; result["applications"]=[str(x) for x in app.get("applicationIds") or []]
    chosen={"NETWORK":nf,"IP_ADDRESS":af,"PORT":pf}.get(typ,{})
    result["match_opposite"]=bool(chosen.get("matchOpposite",False))
    return result


def normalize_policies(data):
    network_by_id,_=_network_maps(data)
    zones={str(z.get("id")):str(z.get("name") or "unknown") for z in data.get("firewall_zones") or []}
    out=[]
    for p in data.get("firewall_policies") or []:
        proto=(p.get("ipProtocolScope") or {}).get("protocolFilter") or {}
        protocol=((proto.get("preset") or {}).get("name") or (proto.get("protocol") or {}).get("name") or "ANY")
        action=p.get("action") or {}; metadata=p.get("metadata") or {}
        out.append(NormalizedPolicy(str(p.get("id") or ""),str(p.get("name") or "unnamed"),bool(p.get("enabled",True)),str(action.get("type") or "UNKNOWN"),
            zones.get(str((p.get("source") or {}).get("zoneId")),"unknown"),zones.get(str((p.get("destination") or {}).get("zoneId")),"unknown"),
            _scope(p.get("source"),network_by_id),_scope(p.get("destination"),network_by_id),str(protocol),[str(x) for x in p.get("connectionStateFilter") or []],
            int(p.get("index",2147483647)),bool(p.get("loggingEnabled",False)),str((p.get("ipProtocolScope") or {}).get("ipVersion") or "unknown"),str(metadata.get("origin") or "unknown"),action.get("allowReturnTraffic")))
    return sorted(out,key=lambda p:p.index)


def zone_networks(data):
    by_id,by_vlan=_network_maps(data); result={}
    for z in data.get("firewall_zones") or []:
        result[str(z.get("name"))]=[by_id.get(str(i),"unresolved") for i in z.get("networkIds") or []]
    network_zone={name:zone for zone,names in result.items() for name in names}
    vlan_zone={vlan:network_zone.get(str(n.get("name")),"unknown") for vlan,n in by_vlan.items()}
    return result,vlan_zone


def _scope_applies(scope, network_name, subnet):
    typ=scope["type"]
    if typ=="ANY": return True,False
    if typ=="NETWORK": return network_name in scope["networks"],False
    if typ=="IP_ADDRESS":
        try: target=ipaddress.ip_network(str(subnet),strict=False)
        except ValueError:return False,False
        for item in scope["addresses"]:
            try:
                candidate=ipaddress.ip_network(item["value"],strict=False)
                if target.subnet_of(candidate) or candidate.subnet_of(target): return True,False
            except ValueError: pass
        return False,False
    if typ in ("PORT","APPLICATION","MAC_ADDRESS"): return True,True
    return False,True


RELATIONSHIPS=[("Guest",99,1),("Guest",99,2),("Guest",99,3),("Guest",99,4),("IoT",3,1),("IoT",3,2),("IoT",3,4),("Family",2,4),("Default",1,4),("Servers",4,1),("Servers",4,2),("Servers",4,3),("Servers",4,5),("Servers",4,99)]


def segmentation_summary(data, policies):
    _,by_vlan=_network_maps(data); _,vlan_zone=zone_networks(data); rows=[]
    for label,src_vlan,dst_vlan in RELATIONSHIPS:
        src=by_vlan.get(src_vlan,{}); dst=by_vlan.get(dst_vlan,{})
        sz=vlan_zone.get(src_vlan,"unknown"); dz=vlan_zone.get(dst_vlan,"unknown")
        applicable=[]
        for p in policies:
            if not p.enabled or p.source_zone!=sz or p.destination_zone!=dz:continue
            sm,sl=_scope_applies(p.source_scope,str(src.get("name")),str(src.get("ip_subnet") or "")); dm,dl=_scope_applies(p.destination_scope,str(dst.get("name")),str(dst.get("ip_subnet") or ""))
            if sm and dm:applicable.append((p,sl or dl or p.protocol!="ANY" or bool(p.connection_states)))
        state="UNKNOWN"; evidence="No applicable policy proved effective behavior."
        limited_seen=False
        for p,limited in applicable:
            if limited:
                limited_seen=True; continue
            state="ALLOWED" if p.action=="ALLOW" else "BLOCKED" if p.action=="BLOCK" else "UNKNOWN"
            if limited_seen:state="LIMITED"
            evidence=f"First conclusive ordered policy: {p.name} ({p.action}, index {p.index}, {p.origin})."
            break
        rows.append({"relationship":f"{label} ({src.get('name','VLAN '+str(src_vlan))}) → {dst.get('name','VLAN '+str(dst_vlan))}","source_zone":sz,"destination_zone":dz,"state":state,"evidence":evidence})
    # Zone-level management relationships cannot be split by VLAN when zones aggregate networks.
    for label,vlan in (("Guest",99),("IoT",3)):
        zone=vlan_zone.get(vlan,"unknown"); ps=[p for p in policies if p.enabled and p.source_zone==zone and p.destination_zone=="Gateway"]
        broad=None;limited_allow=limited_block=False
        for p in ps:
            is_broad=p.source_scope["type"]==p.destination_scope["type"]=="ANY" and p.protocol=="ANY" and not p.connection_states
            if is_broad: broad=p;break
            limited_allow |= p.action=="ALLOW";limited_block |= p.action=="BLOCK"
        if broad:
            state="ALLOWED" if broad.action=="ALLOW" else "BLOCKED"
            if (broad.action=="BLOCK" and limited_allow) or (broad.action=="ALLOW" and limited_block):state="LIMITED"
            ev=f"Ordered scoped policies precede {broad.name} ({broad.action}, index {broad.index})." if state=="LIMITED" else f"Conclusive gateway policy: {broad.name} ({broad.action}, index {broad.index})."
        elif ps: state="LIMITED"; ev=f"{len(ps)} scoped gateway policies were observed; no broad conclusive policy."
        else: state="UNKNOWN"; ev="No gateway policy proved effective behavior."
        rows.append({"relationship":f"{label} → Gateway/management","source_zone":zone,"destination_zone":"Gateway","state":state,"evidence":ev})
    return rows


def _scope_text(scope):
    if scope["type"]=="ANY":return "Any"
    values=scope["networks"] or [x["value"] for x in scope["addresses"]] or [x["value"] for x in scope["ports"]] or scope["applications"] or scope["mac_addresses"]
    return f"{scope['type']}: {', '.join(values) if values else 'scoped'}"


def official_policy_findings(policies):
    findings=[]; seen={}
    low_trust={"Hotspot","IOT Zone"}; trusted={"Internal","Servers Zone","Gateway"}
    for p in policies:
        sig=(p.source_zone,p.destination_zone,p.action,str(p.source_scope),str(p.destination_scope),p.protocol,tuple(p.connection_states),p.enabled)
        if sig in seen and p.origin!="SYSTEM_DEFINED":
            findings.append(Finding("low","Firewall policy quality",f"Duplicate policy candidate: {p.name}",f"Normalized semantics match {seen[sig]!r}; ordering differs or is unknown.","Duplicate policies can complicate review, but equivalence is not proven beyond collected fields.","medium","REVIEW both policies and ordering; do not remove from passive evidence.","correlated",False,"REVIEW",p.as_dict()))
        seen[sig]=p.name
        if not p.enabled:
            findings.append(Finding("informational","Firewall policy quality",f"Disabled policy candidate: {p.name}",f"Policy is disabled at index {p.index}.","Disabled policy may be intentional history or stale configuration.","high","REVIEW purpose; candidate for removal only after human confirmation.","reported",False,"CANDIDATE FOR REMOVAL",p.as_dict()));continue
        if p.action!="ALLOW":continue
        broad=p.source_scope["type"]==p.destination_scope["type"]=="ANY" and p.protocol=="ANY" and not p.connection_states
        title=why=severity=None
        if broad and p.source_zone==p.destination_zone=="unknown":title=f"Any → Any allow candidate: {p.name}";why="Unresolved broad allow semantics require review.";severity="high"
        elif broad and p.source_zone in low_trust and p.destination_zone in trusted:title=f"Broad untrusted-zone allow candidate: {p.name}";why="A broad low-trust path can weaken segmentation.";severity="high"
        elif broad and p.destination_zone=="Servers Zone" and p.origin!="SYSTEM_DEFINED":title=f"Broad access into Servers candidate: {p.name}";why="Broad server access should match documented trust intent.";severity="medium"
        elif broad and p.origin!="SYSTEM_DEFINED" and p.source_zone=="Servers Zone" and p.destination_zone in {"Internal","Hotspot","IOT Zone","Media Zone","Gateway"}:title=f"Broad Servers egress candidate: {p.name}";why="A broad server-originated path may exceed return-traffic intent.";severity="medium"
        elif p.source_zone in low_trust and p.destination_zone=="Gateway" and (broad or any(x["value"] in {"22","443","8443"} for x in p.destination_scope["ports"])):title=f"Untrusted → gateway management candidate: {p.name}";why="Gateway management access from a low-trust zone deserves scrutiny.";severity="high"
        if title:
            ev=f"{p.source_zone} → {p.destination_zone}; source={_scope_text(p.source_scope)}; destination={_scope_text(p.destination_scope)}; protocol={p.protocol}; state={p.connection_states or 'any'}; index={p.index}; origin={p.origin}."
            findings.append(Finding(severity,"Firewall policy",title,ev,why,"high","REVIEW documented intent, scope, and ordering; do not change automatically.","correlated",False,"REVIEW",p.as_dict()))
    return findings


def firewall_analysis(data):
    legacy_findings=[]
    for rule in list(data.get("firewall_rules") or [])+list(data.get("traffic_rules") or []):
        if not rule.get("enabled",True) or str(rule.get("action","allow")).lower() not in {"allow","accept"}:continue
        src=str(rule.get("src") or rule.get("source") or "any");dst=str(rule.get("dst") or rule.get("destination") or "any");name=str(rule.get("name") or "unnamed")
        sl=src.lower();dl=dst.lower();title=why=severity=None
        if sl in {"any","all"} and dl in {"any","all"}:title=f"Any → Any allow candidate: {name}";why="An unrestricted allow can undermine segmentation.";severity="high"
        elif "guest" in sl and any(x in dl for x in ("private","rfc1918","default","family","server","iot")):title=f"Guest → private allow candidate: {name}";why="Guest access to private networks conflicts with isolation intent unless narrowly required.";severity="high"
        elif "iot" in sl and any(x in dl for x in ("default","family","server","management")):title=f"IoT → trusted network allow candidate: {name}";why="Broad IoT access to trusted networks should be limited to documented flows.";severity="high"
        if title:legacy_findings.append(Finding(severity,"Firewall policy",title,f"Legacy normalized source={src}; destination={dst}; action=allow.",why,"medium","REVIEW complete semantics and ordering.","reported",False,"REVIEW"))
    if not data.get("firewall_policies"):
        finding=Finding("informational","Firewall coverage","Official firewall policies unavailable or empty","No official firewall policy objects were available.","Effective segmentation cannot be established.","high","Collect official zones and policies read-only.","not_available",False,"UNKNOWN — INVESTIGATE")
        return [],[],legacy_findings+[finding]
    policies=normalize_policies(data); return policies,segmentation_summary(data,policies),official_policy_findings(policies)+legacy_findings


def firewall_findings(data):
    return firewall_analysis(data)[2]
