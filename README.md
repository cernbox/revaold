# REVA

For configuring the reva-server, create a reva.yaml file like this:

```
ldaphostname: hostname.cern.ch
ldapport: 636
ldapbindusername: "CERN\\user"
ldapbindpassword: password
ldapbasedn: "OU=Users,OU=Organic Units,DC=cern,DC=ch"
ldapsearch: "(samaccountname=%s)"

linkdbhostname: hostname.cern.ch
linkdbport: 3306
linkdbusername: octest
linkdbpassword: octest
linkdbname: cernbox
```


For configuring the oc-prox, create a oc-proxy.yaml file like this:

```
revahost: localhost
revaport: 1093

```

