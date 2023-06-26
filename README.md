# UnLinkable-PCS (ul-PCS)

This system enables to enforce a pre-determined policy on signatures while ensuring the unlinkability of signatures (transactions).

The structure of this repository is as follows:

* `Generic_ul-PCS`: Python code to emulate the proposed Generic UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
  - PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  - Sigma.py: Python code to emulate the described Sigma protocols.
  - SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
  - SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
  - test.py: To test the code.

* `PCS`: Python code to emulate the Generic Standard PCS scheme proposed by Badertscher, Matt and Waldner (TCC’21). Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.

* `RBAC_ul-PCS`: Python code to emulate the proposed Role-based UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  - PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  - Sigma.py: Python code to emulate the described Sigma protocols.
  - SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
  - SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
  - test.py: To test the code.
  
* `ul-PCS_with_SP`: Python code to emulate the proposed UL-PCS scheme with Separable policies. Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- ElGamal.py: Python code to emulate the ElGamal encryption.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.


## Instruction for Ubuntu 22.04
Clone the repo via:

```
git clone https://github.com/Mahdi171/Unlinkable_PCS.git
```

And then change your directory to:
```
cd Unlinkable_PCS/
```

### Prerequisite Packages:
Install Docker and then run the following command to build the docker container:

```
sudo docker build -t ulpcs .
```
Now you can run the test files for any construction of your chose with any arbitrary attribute size. 
Note that you can change "n" to any integer larger than 3.

**Original PCS**

```
sudo docker run ulpcs python3 /app/PCS/test.py n
```


**Generic ul-PCS**

```
sudo docker run ulpcs python3 /app/Generic/test.py n
```


**RBAC ul-PCS**

```
sudo docker run ulpcs python3 /app/RBAC/test.py n
```


**ul-PCS with Seperable Policies**

```
sudo docker run ulpcs python3 /app/SP/test.py n
```
