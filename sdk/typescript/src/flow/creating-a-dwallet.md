# Prerequisites

- A Sui keypair
- A keypair for the class groups

# Creating a DWallet Flow

- Create IkaClient
- Request the DKG first round
- Create a class groups keypair and register it(or use the existing one, so you don't need to
  register it)
- Request the DKG second round
- Accept the encrypted user share

## Create IkaClient

```ts
const ikaClient = new IkaClient({
	suiClient,
	config,
	publicParameters,
});
```

## Request the DKG first round

```ts
const decryptionKeyID = await ikaClient.getDecryptionKeyID();

const transaction = new Transaction();

const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
});

ikaTransaction.requestDWalletDKGFirstRoundAndKeep({
	curve: 0,
	decryptionKeyID,
	coinWithBalance({
		coinType: '0x2::ika::IKA',
		amount: 0,
	})(transaction),
	coinWithBalance({
		coinType: '0x2::sui::SUI',
		amount: 0,
	})(transaction),
	receiver: '0x0',
});

const result = await executeTransaction(transaction);

const startDKGFirstRoundEvents = parseDKGFirstRoundEvents(result.events);

const dwalletID = startDKGFirstRoundEvents[0].event_data.dwallet_id;
```

## Create a class groups keypair and register it

```ts
const transaction = new Transaction();

const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
});

const classGroupsKeypair = createClassGroupsKeypair(seed);

const encryptionKey = classGroupsKeypair.encryptionKey;
const encryptionKeySignature = classGroupsKeypair.encryptionKeySignature;

ikaTransaction.registerEncryptionKey({
	curve: 0,
	encryptionKey,
	encryptionKeySignature,
	encryptionKeyAddress: classGroupsKeypair.encryptionKeyAddress,
});

await executeTransaction(transaction);
```

## Request the DKG second round

```ts
const ikaClient = new IkaClient({
	suiClient,
	config,
	publicParameters,
});

const transaction = new Transaction();

const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
});
```
