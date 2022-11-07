<%!
from pathlib import Path
%>
<%
def primary_fn(f):
    return str(primary_path/f)

primary_path = Path(instance.primary_zone_dir)
%>
// Auto generated; do not edit

include "/etc/bind/*.key";

%for z in instance.zones_ns:
zone "${z.name}" {
    type ${z.type};
    %if z.type == 'primary':
    file "${primary_fn(z.file)}";
    %elif getattr(z,'file', None):
    file "${z.file}";
    %endif
    key-directory "${primary_path}";
    %if getattr(z, 'update_keys', None):
    allow-update {
        %for k in z.update_keys:
        key ${k};
        %endfor
    };
    %endif
    %if getattr(z, 'dnssec_policy', None):
    dnssec-policy ${z.dnssec_policy};
    %endif
};
%endfor
