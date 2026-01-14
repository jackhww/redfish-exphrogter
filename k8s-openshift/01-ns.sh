oc create ns redfish-exporter
oc label ns redfish-exporter openshift.io/user-monitoring=true
oc create sa -n redfish-exporter redfish-exporter