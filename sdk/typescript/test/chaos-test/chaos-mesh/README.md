## Steps to run an Ika network on k8s with a customizable network delay

### 1. Run an Ika network on k8s
Follow the steps in the [README](../README.md) file to run an Ika network on k8s.

### 2. Install Chaos Mesh
Run the following command to install Chaos Mesh:
```bash
curl -sSL https://mirrors.chaos-mesh.org/v2.7.2/install.sh | bash
```

### 3. Introduce network delay
Run the following command from this directory:
```bash
kubectl apply -f ./network-delay.yaml
```

### 4. Remove network delay
Run the following command from this directory:
```bash
kubectl delete networkchaos slow-network-conditions -n ika
```
