$name=$args[0]
scp dist/$name pypiserver@10.1.0.31:/tmp/.
ssh pypiserver@10.1.0.31 "python3 -m twine upload -u 7uw -p \`"$(cat pypi_password)\`" --repository-url http://localhost:18080 /tmp/$name" 
