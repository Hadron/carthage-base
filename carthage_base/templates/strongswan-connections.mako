<%
def adjust_id(id):
    return id.replace('-','_').replace('.','_')
%>
connections {
%for peer in peers:
    ${adjust_id(peer.identity)} {
%if peer.remote_addr:
        remote_addrs = ${peer.remote_addr}, %any
%endif
        %if instance.if_id_in:
        if_id_in = ${instance.if_id_in}
        %endif
        %if instance.if_id_out:
        if_id_out = ${instance.if_id_out}
        %endif
        local {
            certs = strongswan.pem
            id = ${instance.name}
        }
        remote {
            id = ${peer.identity}
        }
        children {
            ${adjust_id(peer.identity)} {
                local_ts = ${instance.child_ts}
                remote_ts = ${peer.remote_ts}
            }
        }
    }
%endfor
}
