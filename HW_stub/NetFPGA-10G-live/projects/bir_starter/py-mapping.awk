#!/usr/bin/awk

# run like: awk -f py-mapping.awk < py-mapping > py-mapping.py

BEGIN {
	n=""
}
{
	# XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_RESET_CNTRS
	# XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_RESET_CNTRS():
	if (/^def .*(BAR.)_.*:/) {
		o=match($0, "BAR."); 
		b=substr($0, o, 4);
		#printf "BAR %s\n", b;
		printf "#%s\n", $0;
		getline;
		printf "#%s\n", $0;
		next;
	}
	if (/^def (.*):/) {
		n=substr($0, 5);
		gsub(":$" ,"", n);
		gsub("\\(\\)$", "", n);
		x=match($0, "_0_");
		s1=substr($0, 0, x+2);
		s2=substr($0, x+3);
		gsub(":$" ,"", s2);
		gsub("\\(\\)$", "", s2);
		ps1=sprintf("%s%s_%s():\n", s1, b, s2);
		ps2=sprintf("%s%s_%s_OFFSET():\n", s1, b, s2);
	}
	if (/return/) {
		printf "%s", ps1;
		printf "    return %s()\n", n;
		printf "%s", ps2;
		printf "    return %s()\n", n;
		n=""
	}
}
END {
}
