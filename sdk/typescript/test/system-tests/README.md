### Chaos Tests Setup
Copy the `.env.example` file to `.env` and set the variables in it with configuration of your choice.

### Run the end to end, epoch switch with new members test
Run the `run a full flow test of adding validators to the next epoch` test from the `./system.test.ts` file.
This test configures the network, deploys it, and performs all necessary steps to execute the test.

IMPORTANT: Set a relatively short EPOCH_DURATION_TIME_MS in the `.env` file so the test completes in a reasonable time.

### Run a custom Ika network on k8s 

### 1. Create Genesis files
Run the following command from this directory to create the genesis files:
```bash
./create-ika-genesis-mac.sh
```

### 2. Deploy the Ika network
Run the `"deploy the ika network from the current directory to the local kubernetes cluster"` test from the 
`./system.test.ts` file.

### 3. Run TS tests against the deployed Ika network
First, run the following command from this directory
```bash
cp ./ika-dns-service.ika.svc.cluster.local/publisher/ika_config.json ../../../../ika_config.json 
```
Now you can run the standard TS tests against your new network.  
You can also run the dedicated tests to kill and start validator nodes from the `./system.test.ts` file.

### Apply fake network conditions to the Ika network
After completing the steps in the "Run a custom Ika network on k8s" section above, you can apply fake network
conditions to the Ika network. In the following steps, we will use Chaos Mesh to introduce network delay.
### 1. Install Chaos Mesh
Run the following command to install Chaos Mesh:
```bash
curl -sSL https://mirrors.chaos-mesh.org/v2.7.2/install.sh | bash
```

### 2. Introduce network delay
Run the following command from this directory:
```bash
kubectl apply -f ./network-delay.yaml
```
You can now run the standard TS tests against your new network with the network delay applied, and see they will take
longer to complete due to the network delay.

### 3. Remove network delay
Run the following command from this directory:
```bash
kubectl delete networkchaos slow-network-conditions -n ika
```
You can play with Chaos Mesh to introduce many other network conditions, such as packet loss, duplication, etc.
Read more about Chaos Mesh [here](https://chaos-mesh.org/docs/).

