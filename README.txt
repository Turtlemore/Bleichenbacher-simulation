Implementation of the BleichenBacher attack.
--------------------------------------------------------------------------------------------------------

Overview:
This is an implementation of the Bleichenbacher attack written in the programming language GO. Running the 
code simulates the core of BleichenBachers attack by decrypting some cipher-text without the user having 
the private key.
---------------------------------------------------------------------------------------------------------

How to run:
* Download the FinalAttack executable

* Alternatively, you can build the executable yourself with the source code 
* First download the file FinalAttack.go and make sure you have golang installed on your system
* Now open the terminal and run the command "go build $FILENAME" 	//e.g. go build FinalAttack.go

* On your terminal of choice, run the executable by inputting its path
---------------------------------------------------------------------------------------------------------

Configurations:
You can run the code with a few configuration to alter the behavior of the simulation.
 
* If you simply run the FinalAttack executable, the attack will done with
	-blind=false, 
		which means no blinding phase, meaning you will be prompted to type a message to be encrypted and then used as the c0 value
	-k=1024
	-e=3
	-prec = 1024, note the precision values simply affect the big.Float numbers and not the actual attack. 
		Note: This value should always be the same as the key-length. 
	-oracle = 1, type 1 oracle, which checks if the plaintext conforms to all properties of PKCS 1.5 

*You can pass the following flags: blind, k, e, prec, to the executable to change the above values. e.g. ./FinalAttack -blind=true -k=2048 -e=9 -prec=1024
* If you have the source code FinalAttack.go you can also build and run the program with flags using go run e.g. go run FinalAttack.go -blind=true -k=2048
	
---------------------------------------------------------------------------------------------------------

Checking correctness:
The program prints usefull information throughout the simulation. Check if the "message found" and the 
"start message" is equal, whenever the attack finishes. 
---------------------------------------------------------------------------------------------------------

Notes:
Be patient, the attack is really slow. The reason being that the attack requires a lot of calls to the oracle
as shown in the results, and because the big.Int operations is rather slow and not that optimized for such
big numbers. 