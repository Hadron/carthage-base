<%namespace name='local_conf', file='named.conf.local.mako' />
<%
import types
named_options = types.SimpleNamespace(**instance.named_options)
%>
options {
	directory "/var/cache/bind";
	dnssec-validation auto;

	listen-on-v6 { any; };
    allow-query { any; };
	${local_conf.addr_list(named_options, 'allow_recursion')}\
    %if "forwarders" in instance.named_options:
	${local_conf.addr_list(named_options, 'forwarders')}\
    %endif
};
