echo "Remaking each DNS hijacking phase script..."

cd ./1-infer_port
make

cd ../2-inject_dns
make

echo "Finished building DNS hijacking scripts."
