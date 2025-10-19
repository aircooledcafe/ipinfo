import ipaddress

ip_private = "192.168.1.1"
ip_public = "144.31.221.84"

print(ipaddress.ip_address(ip_private).is_private)
print(ipaddress.ip_address(ip_public).is_private)