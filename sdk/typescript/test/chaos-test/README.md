## Steps to deploy the Ika network with a configurable scale on a Kubernetes cluster of your choice.

### 1. Set chain values
Copy the `.env.example` file to `.env` and set the variables in it with configuration of your choice.

### 2. Build the Docker image
Run the following command from this directory to build the ika-node docker image:
```bash
./build.sh
```

### 3. Make the docker image available to the local Kubernetes cluster
If you are using Minikube, first save the docker image to a tar file (replace `<DOCKER_TAG>` with the tag you used in the `.env` file):
```bash
docker save <DOCKER_TAG> > node.tar
```
then, copy the container image to the Minikube cluster:
```bash
minikube cp node.tar /home/docker/
```
then ssh into the Minikube cluster and load the image:
```bash
minikube ssh
docker load < node.tar
```

### 4. Create Genesis files
Run the following command from this directory to create the genesis files:
```bash
./create-ika-genesis-mac.sh
```

### 5. Deploy the Ika network
Run the `"deploy the ika network from the current directory to the local kubernetes cluster"` test from the 
`./chaos.test.ts` file.

### 6. Run TS tests against the deployed Ika network
First, run the following command from this directory
```bash
cp ./ika-dns-service.ika.svc.cluster.local/publisher/ika_config.json ../../../../ika_config.json 
```
Then, within `sdk/typescript/test/e2e/dwallet-mpc.test.ts`, make sure the `SUI_FULLNODE_URL` & `SUI_FAUCET_HOST` are pointing
to the same addresses as your previously created `.env` file.
Now you can run the test against your newly deployed Ika network! 🏂
