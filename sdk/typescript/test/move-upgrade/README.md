### How to Upgrade the 2pc-mpc Move Module

### Step 1: Update Move Dependencies to Use Already Deployed Packages
Open `contracts/ika_dwallet_2pc_mpc/Move.toml` and add the following under `addresses`:
ika = "<IKA_PACKAGE_ID>"
Replace `<IKA_PACKAGE_ID>` with the value from `ika_config.json`.

In `contracts/ika/Move.toml`, add the following under `package`:
published-at = "<IKA_PACKAGE_ID>"
Also update the `ika` entry to `<IKA_PACKAGE_ID>`.

In `contracts/ika_common/Move.toml`, add the following under `package`:
published-at = "<IKA_COMMON_PACKAGE_ID>"
Also update the `ika_common` entry to `<IKA_COMMON_PACKAGE_ID>`.
