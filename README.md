# ChainSmith

## Why use ChainSmith
If you want to run Postgres and other tools Enterprise grade you want to use SSL for encryption in transit, and verifying trust.
But creating a simple chain with a root, 2 intermediates, client certificates and/or server certificates is too complex and requires much manual effort.
Or requires o trust a black box implementation where no one understands what actually is happening.
This project is meant to fix this.

With ChainSmith, you can easily define a chain in yaml config, and then run this script to create a root ca, intermediates and signed certificates.
Furthermore, you can bundle all generated certs in either multiple tar files (with readmes), or yaml files ready to be used in an Ansible deployment.
You could even use this project to very easily generate all CSR's to be signed externally, and run with the generated chain until they are.
And the best part, if you understand python, you can see exactly what ChainSmith is doing to get there.

ChainSmith is a crucial piece into improving adoption of running Postgres and other tools with proper security.
And as such systems can be easily equipped with the proper certificate chains so that secure communication and authorization is possible.

## Why use certificates
Certificates are a technical implementation for verification of trustworthiness.
Certificates can be verified on the following points:
- to be used for its correct purpose 
- to be used by the correct person or system
- to be used by a person or system which is trusted by you, or a party you trust
Once trustworthiness is established, certificates can be used to limit communication to only the 2 parties that are communicating.

### How verification of trust works
A certificate can be verified to:
- be used for its proper purpose
  - common name should correspond to the server you are communicating with, or
  - common name should correspond to the user trying to authenticate with it
- be used by the proper system or user
  - the certificate can be shared to everyone that wants to be verified, but
  - the certificate can only be used by those that hold the corresponding private key
- be handed out by someone or something you trust, or someone they trust 
  - Every certificate is signed by another certificate (except for root certificates)
  - Before signing off on a certificate, the authority is required to properly verify that the certificate is requested by the proper person, system or authority
  - this creates a chain of trust
  - if you can trust one certificate in the chain, you can also trust all that are signed by that certificate
- Certificates that can no longer be trusted can be revoked
- Once trust is verified, communication is assured to be protected from anyone besides the 2 parties that are communicating
  - all information encrypted with the certificate can only be decrypted by the system or person with the correct private key

## Development

This project is maintained on [github](https://github.com/MannemSolutions/chainsmith).

If you run into issues while using, or you may have other suggestions to improve ChainSmith, please create an [Issue](https://github.com/MannemSolutions/chainsmith/issues/new/choose).

And if you want to contribute, don't be shy, just create a [Pull Request](https://github.com/MannemSolutions/chainsmith/compare) and we will probably merge.

## License

This software (all code in this github project) is subjective to GNU GENERAL PUBLIC LICENSE version 3.