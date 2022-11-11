<%!
from pathlib import Path
%>\
<%
def primary_fn(f):
    return str(primary_path/f)

primary_path = Path(instance.primary_zone_dir)
%>\
<%def name="addr_list(zone, attr)">\
%if getattr(zone, attr, []):
${attr.replace('_','-')} {
    %for item in getattr(zone, attr):
    ${item};
    %endfor
};
%endif
</%def>

// Auto generated; do not edit

include "/etc/bind/*.key";

%for name, zone in instance.zones_ns.items():
zone "${name}" {
    type ${zone.type};
    %if zone.type == 'primary':
    file "${primary_fn(zone.file)}";
    key-directory "${primary_path}";
    %elif getattr(zone,'file', None):
    file "${zone.file}";
    %endif
    %if zone.type == 'secondary':
    ${addr_list(zone, 'masters')}
    %endif
    %if getattr(zone, 'update_keys', None):
    allow-update {
        %for k in zone.update_keys:
        key ${k};
        %endfor
    };
    %endif
    %if getattr(zone, 'dnssec_policy', None):
    dnssec-policy ${zone.dnssec_policy};
    %endif
    ${addr_list(zone, 'also_notify')}\
    ${addr_list(zone, 'allow_transfer')}\
    };
%endfor

	