### How to fund your dWallet bitcoin address

1. Run a local regtest with `bitcoind -regtest`
2. Create a wallet with `bitcoind -regtest createwallet "mywallet"`
3. Run `bitcoin-cli -regtest getdescriptorinfo "pkh(<ADDRESS>)"`
to get the address's checksum.
4. Import the address with 
    ```
    bitcoin-cli -regtest -rpcwallet=watchonly importdescriptors '[
      {
        "desc": "pkh(<ADDRESS>)#<CHECKSUM>",
        "active": false,
        "timestamp": "now"
      }
    ]'
    ```
5. Run `bitcoin-cli -regtest generatetoaddress 101` to load it with 50 BTC.
