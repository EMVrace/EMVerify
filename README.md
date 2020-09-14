# EMVerify

This is a [Tamarin](https://tamarin-prover.github.io/)-based security analysis of the EMV standard and is the complementary material for our IEEE S&P 2021 paper *The EMV Standard: Break, Fix, Verify*. Further information on this work is available at [https://emvrace.github.io](https://emvrace.github.io/).

## Folder layout

* [models-n-proofs](./models-n-proofs/): contains the auto-generated, target models and their proofs (`.proof`) accommodated in the following two folders:
	* [contact](./models-n-proofs/contact/): contains the files derived from `Contact.spthy`.
	* [contactless](./models-n-proofs/contactless/): contains the files derived from `Contactless.spthy`.
* [tools](./tools/): contains useful scripts:
	* [`collect`](./tools/collect): Python script that summarizes the proofs in an human-readable HTML file. It also generates LaTeX code of the summary table.
	* [`parse_facts`](./tools/parse_facts): Python script that prints all facts of the input model into an output HTML file. It helps detecting mismatching facts, bugs, etc.
	* [`decomment`](./tools/decomment): Python script that prints a comment-free copy of the input model.
* [`Contact.spthy`](./Contact.spthy): generic model of EMV contact.
* [`Contactless.spthy`](./Contactless.spthy): generic model of EMV contactless.
* [`Makefile`](./Makefile): GNU script to generate the target models and run the Tamarin analysis of them.
* `*.oracle`: proof-support oracles.
* `results-*.html`: the analysis results in HTML format.

## Usage

From the two generic models, the Makefile generates what we call *target models*. These are models that are composed of one generic model in addition to extra rules that produce the `Commit` facts, which are used for the properties' (in)validation. A target model is generated and then analyzed with Tamarin, all by using `make` with the appropriate variable instances.

The full set of variables is listed next:

* `generic`: the generic model file (without the `.spthy` extension). Valid instances are:
	* `Contact`, and
	* `Contactless`(default).
* `kernel`: the kernel (which is the EMV jargon for card schemes). Valid instances are:
	* `Mastercard`(default), and
	* `Visa`.
* `auth`: the Offline Data Authentication (ODA) method. Valid instances are:
	* `SDA`,
	* `DDA`,
	* `CDA`(default), and
	* `EMV`.
* `CVM`: the cardholder verification method user/supported. Valid instances are:
	* `NoPIN`,
	* `PlainPIN`,
	* `EncPIN`, and
	* `OnlinePIN`(default).
* `value`: the value of the transaction (i.e., whether it is above the CVM-required limit or not). Valid instances are:
	* `Low`(default), and
	* `High`.
* `oracle`: references the oracle to be used to assist the proofs.
* `decomment`: if set to `yes`, the auto-generated models will have no comments.
* `fix`: if defined (with any value), the input to the SDAD signature in the Visa contactless protocol becomes ⟨NC, CID, AC, PDOL, ATC, CTQ, UN, IAD, AIP⟩. This is the proposed fix that defends against modification of the Application Cryptogram in fDDA transactions.

For example:
```shell
make generic=Contactless kernel=Mastercard auth=CDA CVM=OnlinePIN value=High
```
generates the target model `Mastercard_CDA_OnlinePIN_High.spthy` from the generic model `Contactless.spthy`, analyzes it with Tamarin, and writes the proof into `Mastercard_CDA_OnlinePIN_High.proof`.

## Full-scale analysis 

We have split our analysis of the **40** target models into three groups:

1. `Mastercard_<auth>_<CVM>_<value>`: used for the security analysis of accepted, contactless transactions, which, in the committing agent's perspective:
	* used Mastercard's kernel/protocol,
	* used the ODA method `<auth>`,
	* the card's highest CVM supported was `<CVM>`,
	* the transaction amount was either below (`Low`) or above (`High`) the CVM-required limit, determined by `<value>`.
2. `Visa_<auth>_<value>`: used for the security analysis of accepted, contactless transactions, which, in the committing agent's perspective:
	* used Visa's kernel/protocol,
	* used the processing mode `<auth>`,
	* the transaction amount was either below (`Low`) or above (`High`) the CVM-required limit, determined by `<value>`.
3. `Contact_<auth>_<CVM>_<authz>`: used for the security analysis of accepted, contact transactions, which, in the committing agent's perspective:
	* used the ODA method `<auth>`,
	* used the CVM `<CVM>`, and
	* were authorized offline or online, determined by `<authz>`.

The auto-generated models allow for any type of transactions to take place, the properties are verified only for **accepted transactions that follow the selected target configuration**. All target models are the same except for the rules that produce the `Commit` facts. Such rules do not model any interaction with the adversary, the network, or any other agent, i.e., they are simply rules to produce the `Commit` facts.

The analysis of the EMV contactless protocol was performed using the Tamarin release 1.4.1 on a MacBook Pro laptop running macOS 10.15.4 with a Quad-Core Intel Core i7 @ 2.5 GHz CPU and 16 GB of RAM.

The analysis of the EMV contact protocol was performed using the Tamarin release 1.5.1 on a computing server running Ubuntu 16.04.3 with two Intel(R) Xeon(R) E5-2650 v4 @ 2.20GHz CPUs (with 12 cores each) and 256GB of RAM. Here we used 10 threads and at most 20GB of RAM per target model.

## Auto-generation of target models

To understand the way we instrument the target models auto-generation, consider the following snippet from our `Contactless.spthy` generic model:
```
/*if(Visa)
rule Terminal_Commits_ARQC_Visa:
    let PDOL = <TTQ, $amount, country, currency, date, type, ~UN>
        /*if(DDA) AIP = <'DDA', furtherData> endif(DDA)*/
        /*if(EMV) AIP = <'EMV', furtherData> endif(EMV)*/
        /*if(Low) value = 'Low' endif(Low)*/
        /*if(High) value = 'High' endif(High)*/
        transaction = <~PAN, AIP, CVM, PDOL, ATC, AC, IAD>
    in
    [ Terminal_Received_AC_Visa($Terminal, $Bank, $CA,
        nc, 'ARQC', transaction, ~channelID),
      !Value($amount, value),
      Recv($Bank, $Terminal, <~channelID, 'Visa', '2'>, <'ARC', ARPC>) ]
  --[ TerminalAccepts(transaction),
      Commit(nc, ~PAN, <'Card', 'Terminal', transaction>),
      Commit($Terminal, $Bank, <'Bank', 'Terminal', transaction>),
      Honest($CA), Honest($Bank), Honest($Terminal), Honest(~PAN)]->
    [ ]
endif(Visa)*/
```
This piece of code is *activated* (uncommented), and so the rule becomes part of the target model, if the target configuration contains `kernel=Visa`. Furthermore, depending on the rest of the target configuration, the AIP and value are activated. For example, if our target configuration includes `auth=DDA` and `value=High`, then the rule becomes:
```
rule Terminal_Commits_ARQC_Visa:
    let PDOL = <TTQ, $amount, country, currency, date, type, ~UN>
        AIP = <'DDA', furtherData>
        value = 'High'
        transaction = <~PAN, AIP, CVM, PDOL, ATC, AC, IAD>
    in
    [ Terminal_Received_AC_Visa($Terminal, $Bank, $CA,
        nc, 'ARQC', transaction, ~channelID),
      !Value($amount, value),
      Recv($Bank, $Terminal, <~channelID, 'Visa', '2'>, <'ARC', ARPC>) ]
  --[ TerminalAccepts(transaction),
      Commit(nc, ~PAN, <'Card', 'Terminal', transaction>),
      Commit($Terminal, $Bank, <'Bank', 'Terminal', transaction>),
      Honest($CA), Honest($Bank), Honest($Terminal), Honest(~PAN)]->
    [ ]
```
This (new) rule models the terminal's acceptance of an online-authorized transaction and produces the `Commit` and `TerminalAccepts` facts.

## Valid configurations

The following `make` commands run all possible valid target configurations:

```shell
#=============== Mastercard ================
#SDA
make generic=Contactless auth=SDA CVM=NoPIN value=Low 
make generic=Contactless auth=SDA CVM=NoPIN value=High 
make generic=Contactless auth=SDA CVM=OnlinePIN value=Low 
make generic=Contactless auth=SDA CVM=OnlinePIN value=High 
#DDA
make generic=Contactless auth=DDA CVM=NoPIN value=Low 
make generic=Contactless auth=DDA CVM=NoPIN value=High 
make generic=Contactless auth=DDA CVM=OnlinePIN value=Low 
make generic=Contactless auth=DDA CVM=OnlinePIN value=High 
#CDA
make generic=Contactless auth=CDA CVM=NoPIN value=Low 
make generic=Contactless auth=CDA CVM=NoPIN value=High 
make generic=Contactless auth=CDA CVM=OnlinePIN value=Low 
make generic=Contactless auth=CDA CVM=OnlinePIN value=High 

#================ Visa ===================
#EMV
make generic=Contactless kernel=Visa auth=EMV value=Low 
make generic=Contactless kernel=Visa auth=EMV value=High 
#DDA
make generic=Contactless kernel=Visa auth=DDA value=Low 
make generic=Contactless kernel=Visa auth=DDA value=High 

#=============== Contact ================
#Offline
#SDA
make generic=Contact auth=SDA CVM=NoPIN authz=Offline 
make generic=Contact auth=SDA CVM=PlainPIN authz=Offline 
make generic=Contact auth=SDA CVM=EncPIN authz=Offline 
make generic=Contact auth=SDA CVM=OnlinePIN authz=Offline 
#DDA
make generic=Contact auth=DDA CVM=NoPIN authz=Offline 
make generic=Contact auth=DDA CVM=PlainPIN authz=Offline 
make generic=Contact auth=DDA CVM=EncPIN authz=Offline 
make generic=Contact auth=DDA CVM=OnlinePIN authz=Offline 
#CDA
make generic=Contact auth=CDA CVM=NoPIN authz=Offline 
make generic=Contact auth=CDA CVM=PlainPIN authz=Offline 
make generic=Contact auth=CDA CVM=EncPIN authz=Offline 
make generic=Contact auth=CDA CVM=OnlinePIN authz=Offline 
#Online
#SDA
make generic=Contact auth=SDA CVM=NoPIN authz=Online 
make generic=Contact auth=SDA CVM=PlainPIN authz=Online 
make generic=Contact auth=SDA CVM=EncPIN authz=Online 
make generic=Contact auth=SDA CVM=OnlinePIN authz=Online 
#DDA
make generic=Contact auth=DDA CVM=NoPIN authz=Online 
make generic=Contact auth=DDA CVM=PlainPIN authz=Online 
make generic=Contact auth=DDA CVM=EncPIN authz=Online 
make generic=Contact auth=DDA CVM=OnlinePIN authz=Online 
#CDA
make generic=Contact auth=CDA CVM=NoPIN authz=Online 
make generic=Contact auth=CDA CVM=PlainPIN authz=Online 
make generic=Contact auth=CDA CVM=EncPIN authz=Online 
make generic=Contact auth=CDA CVM=OnlinePIN authz=Online 
```
## Verified fixes for EMV contactless

### Mastercard

Mastercard's most common configuration (i.e. `auth=CDA` and `CVM=OnlinePIN`) used nowadays is secure.

### Visa

**To prevent the PIN bypass attack**, we recommend that:
* **1**: All terminals must the 1st bit of TTQ’s first byte for all transactions, and
* **2**: All terminals must verify the SDAD signature for all transactions.

In conjunction, these two recommendations make high-value transactions be processed with Visa’s secure configuration.

**To prevent the offline attack**, we recommend that either:
* **3(a)**: All terminals set the 8th bit of TTQ’s second byte for all transactions, or
* **3(b)**: The input to the SDAD signature is ⟨NC, CID, AC, PDOL, ATC, CTQ, UN, IAD, AIP⟩.

The recommendation 3(a) makes all transactions be processed online and is preferable over 3(b) because 3(a) does not require changes to the standard and therefore does not affect the consumer cards in circulation. The Tamarin proof of 3(b) is `models-n-proofs/contactless/Visa_DDA_Low_Fix.proof` and one can generate it by running:

```shell
make generic=Contactless kernel=Visa auth=DDA value=Low fix=Yes
```

## Notes

* Different versions of GNU use different regex syntax. Thus, you might need to tweak the regexes in the `sed` commands of the Makefile.
* The authentication properties we use are *non-injective agreement* and *injective agreement* (see their Tamarin specification [here](https://tamarin-prover.github.io/manual/book/006_property-specification.html#authentication)). For each model, if non-injective agreement fails, we do not analyze injective agreement as it fails too given that the latter property is stronger than the former.

## Authors

* [David Basin](https://people.inf.ethz.ch/basin/)
* [Ralf Sasse](https://people.inf.ethz.ch/rsasse/)
* [Jorge Toro](https://jorgetp.github.io)


