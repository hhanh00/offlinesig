# OfflineSig

OfflineSig is a BIP-44 wallet implementation that can work nearly entirely offline. The source code is short enough (~600 lines) that it can be throughfully reviewed for security weaknesses.
But, it's for advanced users who are confortable with making their own transactions.

OfflineSig accepts several commands. The first argument is always the name of the currency. It currently supports
 * BTC
 * tBTC
 * LTC
 * DOGE

Other currencies can easily be added but I don't have any of them to test with.

## seed
Create a new wallet and return the master mnemonic words. The currency is ignored but required for consistency with the other commands.
```
bin\offlinesig BTC seed

Entropy seed = 01d89da8983ee15d01668b9dfb429a54
achieve shaft health corn unlock purse airport sphere over sure pledge practice
```
The entropy seed and the mnemonic words are equivalent. Passing the entropy seed as a parameter outputs the mnemonic words again. This 
lets you use an external source of entropy if you prefer.

```
bin\offlinesig BTC seed 01d89da8983ee15d01668b9dfb429a54

Entropy seed = 01d89da8983ee15d01668b9dfb429a54
achieve shaft health corn unlock purse airport sphere over sure pledge practice
```

Save the mnemonic words in a file (not the entropy hex). We'll call it the *seed-file*. There is only one seed file for all the currencies.

## mpk
Prints out the master watch-only key.

```
bin\offlinesig BTC mpk seed.txt

{"pub":"0360f06d1602c9c98805b3d6a15ca28d43052a9391d0a6c685714eab95a5819180","chain":"7bcaded5bd50a4ef33d720e59c458f2a6d328574c16586f3c0820b25a118c735"}
```

If you want to add a password, you can add it as the second argument.

```
bin\offlinesig BTC mpk seed.txt password

{"pub":"02382ec8ede725a39612bd5bb0a7d84e161e8df462b77c60dc7852cd30ddccd90c","chain":"52679b46169413f63eb5134a5247961ff7afae0172ee47a9d814d070e7fc7fb8"}
```

**Important Note: If you add a password, it will change the addresses generated. Therefore if you don't specify the right password, you will not be able to sign. In other words, there is no way to recover the password. IT IS NOT PART OF THE SEED.
The mpk will change with the currency. I recommend creating a directory per currency where you keep your mpk file.**

Save output into a file. We'll call that file the *mpk-file*.

The first two steps should be performed on your safe, cold-storage, offline, clean machine.
Now, transfer your *mpk-file* to the online computer.

## receive
Generate receive addresses

```
bin\offlinesig BTC receive mpk.txt 5

1H9VtH4WfEsQ8A8hC2PreCeMfVm1mKLVqb
1NS8o84E7u7p9KF7aUhGLaRkJFX7joU4ZH
18vyDx8BsFWYa1S47kn6JNpP6Uo3ChbM2p
152VddzjkffeYFZhqvJbGas7ZVWAqK3xVc
1KRhojk2hrpP8cfVAjW3Mg4zRLrbEsRcEC
```

*If you use multiple currencies, be sure to specify the right mpk-file*

## change
Generate change addresses

```
bin\offlinesig BTC change mpk.txt 5

1BQhv9B5qF8rho1vooP2V3N8VvCMRPP9bW
1MpZF7BtC1KWpDrBZCawgRivnW9Xd3uQy3
1HiDjpax5P4LePfEyqTYkds8cqUdscSWR9
1HPim3sxkxRjoBCqEXLLvVpzDy98fq7rc
13FnH9riHZJkpewc1hRon8BQT1bnQVhTjx
```

## prepare
Prepare a transaction for signing.

This is the most difficult step. The command accepts a JSON file describing the transaction. Here's an example:

```json
{
"inputs": [
  { 
  "tx": "3feeee47838fbeb821af285f1013cd67084e0a4998d0982ba06edcf3653a216d",
  "vout": 0,
  "address": "1KCT43dqTBs4a2dhAFgk3EXvFuPXvCdRRS"
  }
],
"outputs": [
  {
  "value": 50000,
  "address": "1BQhv9B5qF8rho1vooP2V3N8VvCMRPP9bW"
  }
]
}
```
All the inputs must come from your wallet, i.e. the input addresses must be from your wallet.
The output values are in Satoshis. There are 100 000 Satoshis per mBTC.

***This tool only support standard Pay-to-PubHash***

```
bin\offlinesig BTC prepare tx.txt

[{"pub":"5b091792e7a62ec1ab4e5de81573bee3f4076e96","hash":"6caa472a75537399540a07fa16200fdc882e73cd60efba5dbdf3fe5ab32377fc"}]
```

This computes the transaction hash that should be signed. Save this to a file. We'll call it the *unsig-file*.

## sign
Sign the *unsig-file* on the offline computer. 

```
bin\offlinesig BTC sign seed.txt unsig.txt password

[{"pub":"03ebf26082853c8268f1a6f352da503a03e04c82fa6e20d6b0ad1b71a8e2537a05","r":86288972876583973053658540997966245594332706692613479849137741375291563554493,"s":4020462519944649147884011451315888209910904793151397348487271122755044462570}]
```
If a password was used, it must be specified again here. The output is the *sig-file*.

## make
Make the final raw transaction.

Bring the *sig-file* to the online computer.

```
bin\offlinesig BTC make tx.txt sig.txt

01000000016d213a65f3dc6ea02b98d098490a4e0867cd13105f28af21b8be8f8347eeee3f000000006a47304402202252ec1feb9d0f6fc3a64d7306896fc4bf2fa152f414017ec5f8ba05e2dd1c5e02203c3471b47a79bd4b86f8520d943cf2e193a6440320cc45b3b1164e151e446ee2012103ebf26082853c8268f1a6f352da503a03e04c82fa6e20d6b0ad1b71a8e2537a05ffffffff0150c30000000000001976a914722cfae7f31483be6cb35c2ce81dd803bc2b451888ac00000000
```

**Double check / triple check your transaction now. In particular, make sure that you are sending to an address of your wallet and
that you didn't forget to include a change address. The next step is irreversible**
Now you can push that transaction to the network. [Blockchain.info PushTX]

# Files
* seed: The seed file contains sensitive information and allows the generation of all the secret keys. It must be kept on the offline computer. If a password was used, the seed file is not enough. So the password adds an additional layer of security. 
* mpk: The master public key for the Bitcoin chain. Because BIP44 is used and hardened keys are involved, the MPK only gives access to the bitcoin account. The file can be kept on the online computer. In case of loss, an attacker will know all receive/change addresses of your wallet, but can't spend from them.
* tx: The transaction. Will be public information once published.
* unsig: Unsigned data. Contains the digest that should be signed. No sensitive data.
* sig: The signatures of the transaction. Only valid for the given transaction. No sensitive data.

[Blockchain.info PushTX]:https://blockchain.info/pushtx

