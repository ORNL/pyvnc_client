#!/bin/bash
name=$1
scp dist/$name pypiserver@corr-boss:/tmp/.
ssh pypiserver@corr-boss "python3 -m twine upload -u 7uw -p \"$(cat pypi_password)\" --repository-url http://localhost:18080 /tmp/$name" 
