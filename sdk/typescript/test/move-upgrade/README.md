### How to Upgrade the 2pc-mpc Move Package

### Step 1: Update Move Dependencies to Use Deployed Packages
Open `contracts/ika_dwallet_2pc_mpc/Move.toml` and add the following under `addresses`:
```
ika = "<IKA_PACKAGE_ID>"
```
Replace `<IKA_PACKAGE_ID>` with the value from `ika_config.json`.

In `contracts/ika/Move.toml`, add the following under `package`:
```
published-at = "<IKA_PACKAGE_ID>"
```
Also update the `ika` entry to `<IKA_PACKAGE_ID>`.

In `contracts/ika_common/Move.toml`, add the following under `package`:
```
published-at = "<IKA_COMMON_PACKAGE_ID>"
```
Also update the `ika_common` entry to `<IKA_COMMON_PACKAGE_ID>`.

### Step 2: Run the Upgrade Test
Open `sdk/typescript/test/move-upgrade/upgrade-ika-twopc-mpc.test.ts`.
In the test "Update the twopc_mpc package and migrate the dwallet coordinator", update the following values to match the current deployment:
- signer: Use the mnemonic printed in the first log when deploying the IKA packages.
- protocolCapID: One of the objects owned by that signer.
- packagePath: Set to `contracts/ika_dwallet_2pc_mpc`.

After updating these values, run the test. It will upgrade the package and migrate the coordinator object to the new version.

