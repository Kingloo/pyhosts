# pyhosts
Creates include-files of hosts to ban for various DNS servers.

Available DNS servers are __Bind__, __Unbound__ and Windows __HOSTS__ file.

## pyhosts.py
pyhosts.py is a copy-paste of everything into one file, removing and adjusting import statements as makes sense.

## Example
```python pyhosts.py unbound blackhole.txt```

```blackhole.txt``` will contain a list of domains to which your DNS caching server will respond with an NX_DOMAIN, formatted for Unbound.

