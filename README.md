# Redfish iDRAC Exporter for OpenShift

A **Prometheus exporter for Dell iDRAC (Redfish API)** designed for **air-gapped OpenShift environments**.

This exporter exposes **hardware health, inventory, power, thermal, fan, storage, memory, network, and SEL event data** from iDRAC via Redfish, and integrates cleanly with **OpenShift User Workload Monitoring**, **Prometheus**, and **Grafana**.

### Exported Metrics Include

- System health & uptime
- BIOS, firmware, model, service tag, serial
- CPU count & memory size
- Fan RPMs & temperature sensors
- PSU input/output & power consumption
- Storage drive health & capacity
- Memory module inventory & health
- Network adapter & port status
- SEL / Event log entries (as Prometheus annotations)

---

## Architecture

```text
Prometheus (User Workload)
        |
        |  ServiceMonitor
        v
Redfish Exporter (Pod)
        |
        |  Redfish API (HTTPS)
        v
iDRAC (Bare Metal Hosts)
```

### OpenShift Deployment:

```
podman build -t image:tag . 
podman push <imageID> registry.local/<registry>/image:tag 

bash k8s-openshift/01-ns.sh
oc apply -f *
```