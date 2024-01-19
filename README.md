# pyhosts
Creates blackhole files for various DNS servers.

DNS requests will return error code [NX_DOMAIN](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6) (non-existent domain).

Supports **Bind**, **Unbound** and Windows **HOSTS** file.

## Examples

### Unbound
```python3 pyhosts.py unbound blackhole.txt```

In your unbound conf file, add the following to the [server] section:

```include: /path/to/blackhole.txt```

Consider running ```unbound-checkconf``` on your conf file.

### Windows HOSTS File
```python3 pyhosts.py winhosts hosts```

Then move *hosts* to *C:\Windows\system32\drivers\etc\hosts*.

**Consider making a backup of the original first!**

### Bind
```python3 pyhosts.py bind named.conf.local```

Add the following to your named.conf file:

```include "/path/to/named.conf.local";```

The Bind formatter presumes that your "poison zone" is */etc/bind/zones/db.poison*.
This can be changed with sed.

```sed 's/\/etc\/bind\/zones\/db.poison/\/path\/to\/db.poison/g' < named.conf.local > /tmp/named.conf.local```

An example of a "poison zone" file:

```
$ORIGIN tld.
$TTL 300

@		IN		SOA		your-dns-server.tld.	webmaster.tld.	(
	20240118001	;	serial, e.g. YYMMDDXXX
	60			;	refresh
	60			;	retry
	60			;	expire
	60			;	negative cache TTL
				;	times kept short so that a mistake doesn't persist very long
)

@		IN		NS		your-dns-server.tld.

@		IN		A		0.0.0.0
				AAAA	::0

*		IN		A		0.0.0.0
				AAAA	::0
```

Learn more at [Bind9 Documentation](https://bind9.readthedocs.io/en/latest/chapter3.html).

## pyhosts.py
pyhosts.py is all the code copied into a single file.