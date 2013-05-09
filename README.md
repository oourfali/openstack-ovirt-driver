A small POC to work with openstack on top of oVirt.
Contains a compute driver, and a cinder driver.
Was written on top of FOLSOM, and contains limited functionality
(as mentioned above, it is a POC... don't expect clean code :-))

This driver requires that the glance image pre-exist in oVirt (i.e., it looks for an oVirt template with the same name as the requested glance image).
