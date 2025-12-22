# How to sign a Bitcoin transaction using a dWallet

1. Create a dWallet and print its bitcoin public key by running the `should create a DWallet and print its bitcoin 
public key` test from the `./sign.test.ts` file.
2. Derive the Bitcoin address of this public key and load it with some bitcoins using a faucet.
3. Replace the consts at the start of the `should create a raw tx to send bitcoin from given address A to given address 
B, output the raw tx` with your dWallet public key and values of your choice, and run the test to get the TX bytes & the
bytes you need to sign using your dWallet (they are a bit different from the tx bytes).
4. Sign the bytes you need to sign using your dWallet and keep the signature bytes.
5. Use the signature you got to run the `should submit a signed transaction to the bitcoin blockchain` test.
