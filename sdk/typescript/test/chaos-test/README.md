## Steps to deploy the Ika network with a configurable scale on a Kubernetes cluster of your choice.

### 1. Set chain values
Copy the `.env.example` file to `.env` and set the variables in it with configuration of your choice.

### 2. Update teh network's code with the new configuration
Run the following command from this directory:
```bash
./change-committe.sh
```

### 2. Build the Docker image
Run the following command from this directory to build the ika-node docker image:
```bash
./build.sh
```

### 3. Create Genesis files
Run the following command from this directory to create the genesis files:
```bash
./create-ika-genesis-mac.sh
```

### 4. Deploy the Ika network
Run the `"deploy the ika network from the current directory to the local kubernetes cluster"` test from the 
`./chaos.test.ts` file.

### 5. Run TS tests against the deployed Ika network
First, run the following command from this directory
```bash
cp ./ika-dns-service.ika.svc.cluster.local/publisher/ika_config.json ../../../../ika_config.json 
```
Then, within `sdk/typescript/test/e2e/dwallet-mpc.test.ts`, make sure the `SUI_FULLNODE_URL` & `SUI_FAUCET_HOST` are pointing
to the same addresses as your previously created `.env` file.
Now you can run the test against your newly deployed Ika network! 🏂
