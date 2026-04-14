import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import ipaddress

df = pd.read_csv("firewall_traffic.csv", parse_dates=["timestamp"])
df["hour"] = df["timestamp"].dt.hour

print("Dataset:", df.shape)
print(df["action"].value_counts())
hourly = (df.groupby(["hour", "action"]).size()
          .unstack(fill_value=0)
          .reindex(columns=["ALLOW", "DENY"], fill_value=0))

print("\nALLOW/DENY per hour:")
print(hourly)

print("\nTop 10 src_ip:")
print(df["src_ip"].value_counts().head(10))

print("\nTop 10 dst_port:")
print(df["dst_port"].value_counts().head(10))

danger_ports = [4444, 6667, 1080, 9050]
high_risk_allowed = df[(df["dst_port"].isin(danger_ports)) & (df["action"] == "ALLOW")]

print("\nHigh-risk ports ALLOWED (count):", len(high_risk_allowed))
if not high_risk_allowed.empty:
    print(high_risk_allowed[["timestamp", "src_ip", "dst_ip", "dst_port"]].head(10))

print("\nTop 10 bytes_sent:")
print(df.sort_values("bytes_sent", ascending=False)[
      ["timestamp", "src_ip", "dst_ip", "dst_port", "bytes_sent"]].head(10))

dnat = df[df["nat_dst"].notna()][["dst_ip", "dst_port", "nat_dst"]].drop_duplicates()

print("\nDNAT mappings:")
print(dnat if not dnat.empty else "None")

sensitive = [3306, 5432, 3389, 22]
exposed = dnat[dnat["dst_port"].isin(sensitive)]
print("\nSensitive DNAT exposed:")
print(exposed if not exposed.empty else "None")

def is_rfc1918(ip):
    try:
        ip = ipaddress.ip_address(str(ip))
        return (ip in ipaddress.ip_network("10.0.0.0/8") or
                ip in ipaddress.ip_network("172.16.0.0/12") or
                ip in ipaddress.ip_network("192.168.0.0/16"))
    except:
        return False

snat_leaks = df[df["dst_ip"].astype(str).apply(is_rfc1918)]
print("\nSNAT leaks (RFC1918 dst_ip) found:", len(snat_leaks))
os.makedirs("charts", exist_ok=True)
ALLOW = "#2ECC71"
DENY = "#E74C3C"
plt.figure(figsize=(10, 5))
plt.bar(hourly.index, hourly["ALLOW"], color=ALLOW, label="ALLOW")
plt.bar(hourly.index, hourly["DENY"], bottom=hourly["ALLOW"], color=DENY, label="DENY")
plt.title("ALLOW vs DENY Sessions per Hour")
plt.xlabel("Hour")
plt.ylabel("Sessions")
plt.legend()
plt.tight_layout()
plt.savefig("charts/chart1_allow_deny.png")
plt.close()


top_ports = (df.groupby(["dst_port", "action"]).size()
             .unstack(fill_value=0)
             .reindex(columns=["ALLOW", "DENY"], fill_value=0))
top_ports = top_ports.assign(TOTAL=top_ports["ALLOW"] + top_ports["DENY"]) \
                     .sort_values("TOTAL", ascending=False).head(15).drop(columns="TOTAL")

plt.figure(figsize=(10, 6))
plt.barh(top_ports.index.astype(str), top_ports["ALLOW"], color=ALLOW, label="ALLOW")
plt.barh(top_ports.index.astype(str), top_ports["DENY"], left=top_ports["ALLOW"], color=DENY, label="DENY")
plt.title("Top 15 Destination Ports (Split by Action)")
plt.xlabel("Sessions")
plt.ylabel("Destination Port")
plt.legend()
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("charts/chart2_top_ports.png")
plt.close()

top_src = df["src_ip"].value_counts().head(10).index
top_dst = df["dst_port"].value_counts().head(10).index
hm = df[df["src_ip"].isin(top_src) & df["dst_port"].isin(top_dst)]
hm_table = hm.groupby(["src_ip", "dst_port"]).size().unstack(fill_value=0)

plt.figure(figsize=(11, 6))
sns.heatmap(hm_table, cmap="Reds", annot=True, fmt="d")
plt.title("Heatmap: Top 10 Source IPs vs Top 10 Destination Ports")
plt.xlabel("Destination Port")
plt.ylabel("Source IP")
plt.tight_layout()
plt.savefig("charts/chart3_heatmap.png")
plt.close()

print("\nDone. Charts saved in charts/")