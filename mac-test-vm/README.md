# Setting up eBPF in macOS
Step 1: Hypervisor.framework to run VMs. To install it, you can use
```
brew install lima
```

Step 2: Create VM
```
limactl start --name=ubuntu ubuntu-vm.yml
```

Step 3: Start VM
```
limactl shell ubuntu
```
