package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	rand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

var k int = 1024         //Key size in bits, can be changed to values such 512, 1024 and 2048
var e int64 = 3          //Exponent e, can be changed aswell fx. 3, or 65537
var prec uint = 2048     //The precision of the big.Float values adjust values to 512, 1024, 2048, ...
var intervalCounter = 0  //Interval counter is a constant and should not be changed.
var iterationCounter = 1 //iterarionCounter is also a constant but could be change
var keyByteLength int    //if we run the blinding step (NOT IMPLEMENTED, SO DONT CHANGE)

var keyLength string
var keyLengthInt int
var fn string
var output string
var oracleFormatToCheck string
var oracleType int
var startMessageBlock string
var startTime time.Time
var startTimeBlinding time.Time
var totalOracleCalls = 0
var isConforming = false
var reader = crand.Reader
var intQuotient big.Float
var rndStartCipher big.Int //Reserved for the random ciphertext generated when using the blinding step.
var randomMessage string   //Reserved for the random initial message (Decrypted ciphertext from above).
var useBlinding = false    //Boolean to enable(true) and disable(false) the blinding-step

var s0 big.Int
var si big.Int
var c0 big.Int
var ss0 big.Int
var newA big.Int
var newB big.Int
var twoB big.Int
var threeB big.Int
var threeBMin1 big.Int
var oracleKey big.Int
var publickey big.Int
var initStartVal big.Int
var aValuesList []big.Int
var bValuesList []big.Int
var initStartValue big.Int

//Big.Int constants for easy use
var z0 = new(big.Int).SetInt64(0)
var z1 = new(big.Int).SetInt64(1)
var z2 = new(big.Int).SetInt64(2)
var z3 = new(big.Int).SetInt64(3)
var z5 = new(big.Int).SetInt64(5)
var zz10 = new(big.Int).SetInt64(10)
var zf0 = new(big.Float).SetInt64(0)
var zf1 = new(big.Float).SetInt64(1)
var zf16 = new(big.Float).SetInt64(16)
var fbase = new(big.Float).SetInt64(16)
var z16 = new(big.Int).SetInt64(16)

func main() {

	kPtr := flag.Int("k", 1024, "the byte-length of n")
	ePtr := flag.Int("e", 3, "the value of e")
	precPtr := flag.Int("prec", 2048, "the precision value")
	blindPtr := flag.Bool("blind", false, "blinding phase flag") //Set blinding flag, set as false per default
	oraclePtr := flag.Int("oracle", 1, "the type of oracle to be used in the attack")

	flag.Parse()

	k = *kPtr
	e = int64(*ePtr)
	prec = uint(*precPtr)
	useBlinding = *blindPtr
	oracleType = *oraclePtr
	if oracleType < 1 || oracleType > 3 {
		fmt.Println("Error invalid oracle type, value must be between 1 and 3, got: ", oracleType)
		return
	}
	useBlinding = *blindPtr
	fmt.Println("")
	fmt.Println("Key size")
	fmt.Println(k)
	fmt.Println("")
	n, d := keyGen(k)        //Generates RSA public and private keys with a bit length of k.
	setUpConstants(n, d)     //Sets up constants like B, 2B, 3B, startvlaue and initial interval.
	startAttack(useBlinding) //Starts the attack depending on whether or not we use the blinding-step
}

func startAttack(useBlinding bool) {
	//*Takes as input the useBlinding boolean indicating whether or not
	//*the attack should run the blinding-step. If it's set to true, we
	//*generate a random ciphertext which isn't PKCS conformant and runs
	//*the attack with the blinding-step, otherwise we prompt the user for
	//*a message which is converted to a PKCS conforming message block and
	//*the attack is run without the blindingstep.
	if useBlinding {
		fmt.Println("Creating a random cipher so we can test the blinding step")
		iterationCounter = 0                               //Sets the iteration counter to 0
		rndStartCipher = createRndCipherMessage(publickey) //Creating a random message/cipher
		fmt.Println("")
		fmt.Println("Start value to test: " + initStartValue.Text(10))
		startTimeBlinding = time.Now()                                  //Meassure start time
		printQueingOracle()                                             //Print out queing the oracle
		bleichenBacherAttack(rndStartCipher, publickey, initStartValue) //Run the attack with blinding-step
	} else {
		fmt.Println("")
		fmt.Println("Enter your message") //Prompt user for input message
		reader5 := bufio.NewReader(os.Stdin)
		fmt.Print(">")
		msg, _ := reader5.ReadString('\n')
		message := strings.TrimSpace(msg)

		setUpInitialInterval()
		startMessage := createFormat(message) //Create a PKCS conforming message block
		startCipher := Encrypt(startMessage, publickey)
		startTime = time.Now()
		printQueingOracle()
		bleichenBacherAttack(startCipher, publickey, s0) //Run the attack without the blinding-step
	}
}

//Main functions for the attack:
func createFormat(message string) big.Int {
	//*Takes as input the message that the user has typed in.
	//*Creates a correctly padded message block, given some message.
	//*Return the decimal version of the correctly padded message block.
	fmt.Println("########################################################################---CREATING FORMAT---########################################################################")
	fmt.Println("")
	var padding string

	zeroTwoAsString := []byte{0x00, 0x02}                      //Sets the two first bytes in the padding format to "00" and "02".
	zeroAsString := []byte{0x00}                               //Sets the seperator byte in the padding format to "00".
	encodedStr := hex.EncodeToString([]byte(zeroTwoAsString))  //Encodes the "00" and "02" bytes into a hex string.
	encodedzeroStr := hex.EncodeToString([]byte(zeroAsString)) //Encodes the seporator byte "00" into a hex string.
	encodedmessage := hex.EncodeToString([]byte(message))      //Encodes the message into a hex string
	mesLength := len(encodedmessage)                           //Sets the length of the message.

	padToAdd := keyLengthInt - mesLength - 6 //Calculate how much padding is needed.
	fmt.Println("Padding to add:   " + strconv.Itoa(padToAdd))
	padding = RandomString(padToAdd) //Creates the random padding using the RandomString method with
	//the amount from the above line.
	pkcsStr := encodedStr + padding + encodedzeroStr + encodedmessage //Construct a full message block such as: "00|02|padding|00|message"

	fmt.Println("Message block:    " + pkcsStr)
	startMessageBlock = pkcsStr
	hex2intEncode := HexToDec(pkcsStr) //Convert this message block from hexadecimal to decimal.
	return hex2intEncode
}

func bleichenBacherAttack(m0 big.Int, n big.Int, start big.Int) {
	//*Takes as input the initial message m0, the public key n and the startvalue start.
	//*This is the method that simulates the bleichenbacher attack going through the
	//*four steps, seaching and narrowing down the intervals until a soution is found.

	//Step 1. Blinding step.
	if iterationCounter == 0 {
		fmt.Println("STARTING STEP 1: blinding step")
		ss0 = *new(big.Int).SetInt64(1)
		for {
			isConforming = queryCreatedMessage(m0, ss0, n)
			ss0.Add(&ss0, z1)
			if isConforming {
				fmt.Println("")
				fmt.Println("The value of s0 that made it pkcs conforming: " + ss0.Text(10))
				fmt.Println("")
				ss0.Sub(&ss0, z1)
				iterationCounter = 1
				setUpInitialInterval()
				var exponent big.Int
				exponent.SetInt64(e)
				c0 = *c0.Exp(&ss0, &exponent, z0)
				c0 = *c0.Mul(&m0, &c0)
				c0 = *c0.Mod(&c0, &n)
				m0 = c0
				break
			}
		}
	}

	//Step 2.a, Starting the search.
	if iterationCounter == 1 {
		fmt.Println("STARTING STEP 2.A: Searching for a conforming message")
		c0 = m0
		for {
			isConforming = queryCreatedMessage(c0, start, n)
			start.Add(&start, z1)
			s0 = start
			if isConforming {
				fmt.Println("")
				fmt.Println("The value of s1 that made it pkcs conforming: " + start.Text(10))
				fmt.Println("")
				start.Sub(&start, z1)
				si = start
				break
			}
		}
		//Step 2.b, Searching with more than one intervals left.
	} else if intervalCounter >= 2 && iterationCounter > 1 {
		//fmt.Println("STARTING STEP 2.B: More intervals for m0 start searching agian")
		time.Sleep(2 * time.Second)
		for {
			isConforming = queryCreatedMessage(c0, si, n)
			si.Add(&si, z1)
			if isConforming {
				fmt.Println("The value of si that made it pkcs conforming: " + si.Text(10))
				fmt.Println("")
				si.Sub(&si, z1) //si that made it pkcs conforming and also si-1 for the next iterations
				break
			}
		}
		//Step 2.c, Searching with one interval left
	} else if intervalCounter == 1 {
		//fmt.Println("STARTING STEP 2.C: Searching with one interval left")
		ri := calculateROneInterval(newB, n, si) //Set initial value for ri
		for {
			resultSi := onlyOneIntervalLeft(c0, n, ri)
			ri.Add(&ri, z1)
			if isConforming {
				si = resultSi
				break
			}
		}
	}
	//Step 3 (Narrowing the intervals)
	if intervalCounter >= 2 {
		//fmt.Println("STARTING STEP 3: Narrowing down when there is more intervals")
		narrowMoreInterval(c0, n, si) //If there are more intervals
	} else {
		//fmt.Println("STARTING STEP 3: Narrowing down when there is only one interval")
		narrowInterval(c0, n, si) //If there is only one inteval
	}

	//Step 4, Computing the solution.
	if iterationCounter > 1 && aValuesList[len(aValuesList)-1].Cmp(&bValuesList[len(bValuesList)-1]) == 0 &&
		intervalCounter == 1 && !useBlinding {
		m0AsMes := bigInt2BigFloat2String(aValuesList[len(aValuesList)-1])
		elapsed := time.Since(startTime)
		fmt.Println("########################################################################---ATTACK SUCCESSFUL!---##########################################################################")
		fmt.Println("")
		fmt.Println("message block found:          " + "000" + m0AsMes)
		fmt.Println("Start Message for comparison: " + startMessageBlock)
		fmt.Println("start value s0:               " + initStartValue.Text(10))
		fmt.Println("Attack finished in :          " + strconv.Itoa(totalOracleCalls) + " oracle calls")
		fmt.Printf("Attack took:                  %.0f seconds.", elapsed.Seconds())
		fmt.Println("")
		plainTextFromAttack := repeatTrimUntil00(m0AsMes)
		finalPlainText := trimLeftChar(plainTextFromAttack, 1)
		fmt.Println("Plaintext:                    " + finalPlainText)
		fmt.Println("")
		plaintextChar, _ := hex.DecodeString(finalPlainText)
		translatedPlainText := string(plaintextChar)
		fmt.Println("Readable plaintext:           " + translatedPlainText)
		fmt.Println("")
	} else if iterationCounter > 1 && aValuesList[len(aValuesList)-1].Cmp(&bValuesList[len(bValuesList)-1]) == 0 &&
		intervalCounter == 1 && useBlinding {
		var m big.Int
		var modInv big.Int
		elapsed := time.Since(startTimeBlinding)
		modInv = *modInv.ModInverse(&ss0, &publickey)
		m = *m.Mul(&aValuesList[len(aValuesList)-1], &modInv)
		m = *m.Mod(&m, &publickey)
		m0AsMesBlind := bigInt2BigFloat2String(m)
		fmt.Println("########################################################################---ATTACK SUCCESSFUL!---##########################################################################")
		fmt.Println("")
		fmt.Println("message block found:          " + m0AsMesBlind)
		fmt.Println("Start Message for comparison: " + randomMessage)
		fmt.Println("start value:                  " + initStartValue.Text(10))
		fmt.Println("First conformant s0:          " + ss0.Text(10))
		fmt.Println("Attack finished in :          " + strconv.Itoa(totalOracleCalls) + " oracle calls")
		fmt.Printf("Attack took:                  %.0f seconds.", elapsed.Seconds())
		fmt.Println("")
	} else {
		iterationCounter += 1
		bleichenBacherAttack(c0, n, si)
	}
}

func calculateROneInterval(b big.Int, n big.Int, si big.Int) big.Int {
	//*Takes as input some interval value b, the public key n and some value of si.
	//*With these inputs the value of r is computed such that r >= 2*((bsi-2B)/n)
	var newR big.Int

	newR = *newR.Mul(&b, &si)      //b*si
	newR = *newR.Sub(&newR, &twoB) //b*si-2B
	newR = *newR.Div(&newR, &n)    //(b*si-2B)/n
	newR = *newR.Mul(z2, &newR)    //2*((b*si-2B)/n)
	return newR
}

func calculateSi(a big.Int, b big.Int, key big.Int, ri big.Int) (big.Int, big.Int) {
	//*Takes as input some interval values a,b the public key and the value for ri.
	//*Then the lowerbound and upperbound for the Si value is computed and returned.
	var lowerBound big.Int
	var upperBound big.Int

	lowerBound = *lowerBound.Mul(&ri, &key)          //ri*n
	lowerBound = *lowerBound.Add(&twoB, &lowerBound) //2B+rn
	lowerBound = *lowerBound.Div(&lowerBound, &b)    //((2b+rn)/b)

	upperBound = *upperBound.Mul(&ri, &key)            //ri*n
	upperBound = *upperBound.Add(&threeB, &upperBound) //3B+ri*n
	upperBound = *upperBound.Div(&upperBound, &a)      //((3B+ri)/a)

	return lowerBound, upperBound
}

func calculateR(a big.Int, b big.Int, key big.Int, si big.Int) (big.Int, big.Int) {
	//*Takes as input some interval values a,b then it takes the public key n and some value of si.
	//*This method is used to compute the lowerbound and upperbound of the r values computer from
	//*the si value that made the initial message pkcs#1v1.5 conforming. The lowerbound and
	//*the upperbound is returned.
	var valTwoB big.Int
	var threeBPlus1 big.Int
	var lowerBound big.Int
	var upperBound big.Int

	valTwoB = *valTwoB.Mul(&a, &si)                      //initially 2B*s1, in iterations afterwards a*si
	threeBPlus1 = *threeBPlus1.Add(&threeB, z1)          //always 3B + 1
	lowerBound = *lowerBound.Sub(&valTwoB, &threeBPlus1) //initially 2B*s1 - 3B+1, in iterations afterwards a*si - 3B+1
	lowerBound = *lowerBound.Div(&lowerBound, &key)      //initially (2B*s1 - 3B+1)/n, in iterations afterwards (a*si - 3B+1)/n

	upperBound = *upperBound.Mul(&b, &si)            //Initially (3B-1)*s1, in iterations afterwards it will be (b*si)
	upperBound = *upperBound.Sub(&upperBound, &twoB) //Initially (3B-1)*s1)-2B, in iterations afterwards it will be (b*si)-2B
	upperBound = *upperBound.Div(&upperBound, &key)  //Initially ((3B-1)*s1)-2B)/n, in iterations afterwards it will be ((b*si)-2B)/n

	return lowerBound, upperBound //return (2B*s1 - 3B+1)/n <= r <= ((3B-1)*s1)-2B)/n, or (a*si - 3B+1)/n <= r <= ((b*si)-2B)/n
}

func calculateNewInterval(r big.Int, si big.Int, n big.Int) (big.Int, big.Int) {
	//*Takes as input the value of r, the vlaue of si and the public key n.
	//*This method calculates the new inetervals based on the si vlaue that
	//*made the message pkcs#1v1.5 conforming.
	var threeBMinus1 big.Int
	var newLowerBound big.Int
	var newUpperBound big.Int

	newLowerBound = *newLowerBound.Mul(&r, &n)                //Does, r*n
	newLowerBound = *newLowerBound.Add(&twoB, &newLowerBound) //Does, 2B + r*n
	newLowerBound = *newLowerBound.Div(&newLowerBound, &si)   //Does, (2B + r*n)/si
	newLowerBound = *newLowerBound.Add(&newLowerBound, z1)    //(To ensure roudning up).

	newUpperBound = *newUpperBound.Mul(&r, &n)                        //Does, r*n
	threeBMinus1 = *threeBMinus1.Sub(&threeB, z1)                     //Does, 3B-1
	newUpperBound = *newUpperBound.Add(&threeBMinus1, &newUpperBound) //Does, (3B-1) + r*n
	newUpperBound = *newUpperBound.Div(&newUpperBound, &si)           //Does, ((3B-1) + r*n)/si

	return newLowerBound, newUpperBound
}

func narrowInterval(m0 big.Int, n big.Int, si big.Int) {
	//*Takes as input the initial message, the public key n and the value of si.
	//*This method is to narrow down the interval when ever we are in the case
	//*where Mi contains only one interval. This is part of step 3.* Here we go thorugh
	//*the interval, we calculate lower and upperbounds for new r values, and
	//*then for each of those r values we calculate new intervals and compare/intersect
	//*them with the old ones. That is done by doing the Max(a, lowerbound) and
	//*Min(b, upperbound).
	var lb big.Int
	var ub big.Int
	var prevLb big.Int
	var prevUb big.Int
	prevLb = aValuesList[len(aValuesList)-1]
	prevUb = bValuesList[len(bValuesList)-1]
	lb, ub = calculateR(newA, newB, n, si)

	for i := new(big.Int).Set(&lb); i.Cmp(&ub) < 0 || i.Cmp(&ub) == 0; i.Add(i, z1) { //rlInt; i <= ruInt; i++ {
		a, b := calculateNewInterval(*i, si, n) //Calculate new interval of m0 such: a = (2B+rn)/si <= m0 <= b= (3B-1+rn)/si

		if prevLb.Cmp(&a) == 1 { //Computes Max(2B, newLowerBound)
			newA = prevLb
		} else {
			newA = a
		}
		if prevUb.Cmp(&b) == 1 { //Computes Min(3B-1, newLowerBound)
			newB = b
		} else {
			newB = prevUb
		}

		if newA.Cmp(&newB) == -1 || newA.Cmp(&newB) == 0 &&
			newA.Cmp(&aValuesList[0]) == -1 || newA.Cmp(&aValuesList[0]) == 1 {
			aValuesList = append(aValuesList, newA)
			bValuesList = append(bValuesList, newB)
		} else {
			aValuesList = remove(aValuesList, len(aValuesList)-1)
			bValuesList = remove(bValuesList, len(bValuesList)-1)
			aValuesList = append(aValuesList, newA)
			bValuesList = append(bValuesList, newB)
		}
	}
	if len(aValuesList) > 1 && len(bValuesList) > 1 {
		aValuesList = remove(aValuesList, 0)
		bValuesList = remove(bValuesList, 0)
	}
	intervalCounter = len(aValuesList)
	si = *si.Add(&si, z1)
}

func narrowMoreInterval(m0 big.Int, n big.Int, si big.Int) {
	//*Takes as input the initial message, the public key n and the value of si.
	//*This method is to narrow down the interval when ever we are in the case
	//*where Mi contains > 1 interval. This is part of step 3.* Here we go thorugh
	//*every intervval, we calculate lower and upperbounds for new r values, and
	//*then for each of those r values we calculate new intervals and compare/intersect
	//*them with the old ones. That is done by doing the Max(a, lowerbound) and
	//*Min(b, upperbound).
	var lb big.Int
	var ub big.Int
	var newAvalList []big.Int
	var newBvalList []big.Int
	numberOfAIntervals := len(aValuesList)
	fmt.Println("Number of intervals for m0 currently: " + strconv.Itoa(numberOfAIntervals))
	fmt.Println("")

	for x0 := 0; x0 < numberOfAIntervals; x0++ { //For each interval
		if len(newAvalList) != len(aValuesList) {
			newAvalList = append(newAvalList, *z0)
			newBvalList = append(newBvalList, *z0)
		}
		lb, ub = calculateR(aValuesList[x0], bValuesList[x0], n, si) //Calculate the lower and upperbound for R
		for r := new(big.Int).Set(&lb); r.Cmp(&ub) < 0 || r.Cmp(&ub) == 0; r.Add(r, z1) {

			a, b := calculateNewInterval(*r, si, n) //Caluculate the new intervals a,b

			if aValuesList[x0].Cmp(&a) == 1 { //Computes Max(a,olda)
				newA = aValuesList[x0]
			} else {
				newA = a
			}
			if bValuesList[x0].Cmp(&b) == 1 { //Computes Min(b,oldb)
				newB = b
			} else {
				newB = bValuesList[x0]
			}

			if newA.Cmp(&newB) == -1 || newA.Cmp(&newB) == 0 { //Only use then new intervals when the newA < newB
				newAvalList[x0] = newA
				newBvalList[x0] = newB

				if len(newAvalList) > 0 && len(newBvalList) > 0 {
					aValuesList = newAvalList
					bValuesList = newBvalList
					for i, _ := range aValuesList {
						if i != x0 {
							remove(aValuesList, i)
						}
					}
					for j, _ := range bValuesList {
						if j != x0 {
							remove(bValuesList, j)
						}
					}
					numberOfAIntervals = len(aValuesList)
				}
			}
		}
	}
	intervalCounter = len(aValuesList)
	fmt.Println("Narrowed the interval down to: " + strconv.Itoa(intervalCounter) + ". intervals")
	fmt.Println("")
	si = *si.Add(&si, z1)
}

func onlyOneIntervalLeft(m0 big.Int, n big.Int, ri big.Int) big.Int {
	//*This method takes the initial message m0, the public key n and the calculated
	//*bound for r. This is equivalent to step 2.c in the bleichenbacker paper/attack
	//*which is the case where our Mi only contains 1 interval {[a,b]}. Then we use
	//*the computed value for ri to compute another integer value si. Then we
	//*multiply the si value with the message m0, for all values of si and queue the oracle.
	var stBig big.Int
	newA = aValuesList[len(aValuesList)-1]
	newB = bValuesList[len(bValuesList)-1]
	si1, si2 := calculateSi(newA, newB, n, ri)
	for i := new(big.Int).Set(&si1); i.Cmp(&si2) < 0 || i.Cmp(&si2) == 0; i.Add(i, z1) {
		stBig = *i
		isConforming = queryCreatedMessage(m0, stBig, n)
		if isConforming {
			return stBig
		}
	}
	return stBig
}

func queryCreatedMessage(cipher0 big.Int, si big.Int, key big.Int) bool {
	//*Takes as input the initial cipherText c0, some integer value si, and the RSA public key.
	//*Computes a new message given then value of si and sends it to the oracle.
	//*Return if the message created and sent to the oracle was conforming.
	var c0xsiExp big.Int
	var siExp big.Int
	var exponent big.Int
	exponent.SetInt64(e)

	siExp = *siExp.Exp(&si, &exponent, z0)     //s^e
	c0xsiExp = *c0xsiExp.Mul(&cipher0, &siExp) //c0*s^e
	c0xsiExp = *c0xsiExp.Mod(&c0xsiExp, &key)  //c0*s^3 mod n
	conforming := Oracle(key, c0xsiExp)
	return conforming
}

func Oracle(pk big.Int, c0ForSimulation big.Int) bool {
	cipher := Decrypt(c0ForSimulation, pk, &oracleKey)
	simOutput1 := bigInt2BigFloat2String(cipher)
	oracleFormatToCheck = "000" + simOutput1
	totalOracleCalls += 1

	if len(oracleFormatToCheck) == keyLengthInt { //Checks if the format size is correct (same length of the key)
		if strings.HasPrefix(oracleFormatToCheck, "0002") { //Check if the format starts with 0002
			if oracleType == 2 {
				return true
			}
			trimmedString := trimLeftChar(oracleFormatToCheck, 3)
			res1 := strings.Split(trimmedString, "00")
			first := res1[:1]
			str2 := strings.Join(first, " ")

			if strings.Contains(trimmedString, "00") { //Checks if the format contains a seporator byte "00"
				if oracleType == 3 {
					return true
				}
				if len(str2) < 16 { //If the padding has 00 byte it checks whether it is within the first 16 bits / 8 bytes
					return false //<-- 16 is the default and ensures that there is no 0's in the first 8 bytes of padding.
				} else {
					fmt.Println("The cipher was pkcs conforming!") //Format was pkcs conforming so return true here.
					return true
				}
			} else { //The padding scheme did not contain a 00 byte so no seperator
				return false
			}
		} else { //The padding format didn't start with 0002 so the scheme is incorrect
			return false
		}
	} else { //The size/length of the format was not correct.
		return false
	}
}

//Helper functions
func Encrypt(message big.Int, n big.Int) big.Int {
	//*Takes as input some messgae and the RSA public key.
	//*This function encrypts a message using the RSA public key.
	//*Returns the cipherText c.
	var c big.Int
	var exponent big.Int
	exponent.SetInt64(e)           //Sets the exponent e. (This can be ajusted in the fields)
	c.Exp(&message, &exponent, &n) //m^e mod n
	fmt.Println("Encrypted message: " + c.Text(10))
	return c
}

func Decrypt(cipherText big.Int, n big.Int, d *big.Int) big.Int {
	//*Takes as input the cipherText, the RSA public key and the RSA private key.
	//*It decrypts the ciphertext using the RSA public and the private key.
	//*Return the decrypted message m.
	var z0 big.Int
	var m big.Int
	z0.SetInt64(0)
	m.Exp(&cipherText, d, &n) //m = c^d mod n
	return m
}

func keyGen(k int) (big.Int, big.Int) {
	//This method generates two k-bit RSA key. Given some integer itr generates a public and a private key
	//for encryption and decryption. The method uses the crypy/rand libarary and generates two large primes
	//which is multiplied to get the public-key
	var d big.Int
	var mod big.Int
	var z1 big.Int
	var z2 big.Int
	var n big.Int

	p, _ := crand.Prime(reader, k/2)
	q, _ := crand.Prime(reader, k/2)

	n.Mul(p, q)
	z1.SetInt64(1)
	z2.SetInt64(e)
	z0.SetInt64(0)
	p.Sub(p, &z1)
	q.Sub(q, &z1)
	mod.Mul(p, q)
	d.ModInverse(&z2, &mod)
	for d.Cmp(z0) == 0 {
		return keyGen(k)
	}
	fmt.Println("Public key-factor n: " + n.Text(10))
	fmt.Println("")
	return n, d
}

//Misc Helper functions
func remove(slice []big.Int, s int) []big.Int {
	//*Removes an element from a slice with the given index i
	return append(slice[:s], slice[s+1:]...)
}

func decToHex(input big.Float) string {
	//*Takes as input a decimal value in big.float
	//*Converts a deccimal number into a hexadecimal number
	//*This inpot is a big.float because we need the decimals to compute the remaider.
	var rs string
	var remainderStr string
	var prevVal big.Float
	init := input

	intQuotient.Quo(&input, zf16)   //input divided with 16
	for intQuotient.Cmp(zf0) == 1 { //If the result is not equal 0
		strQuotient := intQuotient.Text('f', 100) //converts the quotient to a string
		res1 := strings.Split(strQuotient, ".")   //Split that string where a "." occurs
		deci := "0." + res1[len(res1)-1]          //Give the decimal part of the string, so 0.xxx
		nFloat := new(big.Float)
		nFloat, _ = nFloat.SetPrec(prec).SetString(deci) //Convert this part back to a float
		remainderTest := nFloat.Mul(nFloat, fbase)       //Calculate the remaider
		reStr := remainderTest.String()                  //The remaider as a string

		if reStr == "0" { //Go through every remainder and
			rs = "0" //
			remainderStr = remainderStr + rs
		} else if reStr == "1" {
			rs = "1"
			remainderStr = remainderStr + rs
		} else if reStr == "2" {
			rs = "2"
			remainderStr = remainderStr + rs
		} else if reStr == "3" {
			rs = "3"
			remainderStr = remainderStr + rs
		} else if reStr == "4" {
			rs = "4"
			remainderStr = remainderStr + rs
		} else if reStr == "5" {
			rs = "5"
			remainderStr = remainderStr + rs
		} else if reStr == "6" {
			rs = "6"
			remainderStr = remainderStr + rs
		} else if reStr == "7" {
			rs = "7"
			remainderStr = remainderStr + rs
		} else if reStr == "8" {
			rs = "8"
			remainderStr = remainderStr + rs
		} else if reStr == "9" {
			rs = "9"
			remainderStr = remainderStr + rs
		} else if reStr == "10" {
			rs = "a"
			remainderStr = remainderStr + rs
		} else if reStr == "11" {
			rs = "b"
			remainderStr = remainderStr + rs
		} else if reStr == "12" {
			rs = "c"
			remainderStr = remainderStr + rs
		} else if reStr == "13" {
			rs = "d"
			remainderStr = remainderStr + rs
		} else if reStr == "14" {
			rs = "e"
			remainderStr = remainderStr + rs
		} else if reStr == "15" {
			rs = "f"
			remainderStr = remainderStr + rs
		}
		prevVal = init
		//For the iteration sake, compute
		init.Quo(&prevVal, zf16)                                //new init value as prevous init divided by 16
		newInitStr := init.Text('f', 100)                       //Convert this result to a string
		res2 := strings.Split(newInitStr, ".")                  //Split the string where a "." occurs
		first := res2[len(res2)-2]                              //Take the first part of the float string
		initFloat := new(big.Float)                             //Set the first part as a float again
		initFloat, _ = initFloat.SetPrec(prec).SetString(first) //Set this as the new initial value
		init = *initFloat                                       //Compute the new quotient for the next
		intQuotient.Quo(&init, zf16)                            //iteration by doing initial value divided with 16
	} //Set the string of remainders to the empty string
	rs = ""                      //if non of the above cases are chosen. (Should not happen)
	return reverse(remainderStr) //Return the reverse of that string.
}

func HexToDec(input string) big.Int {
	//*Takes as input a hex string.
	//*This function converts a hex string to decimal number .
	var val big.Int
	var totalval big.Int
	var base = new(big.Int).SetInt64(16)   //Since we are working with hex the base is set to 16.
	var counter = new(big.Int).SetInt64(1) //An iteration counter set to 1.
	var exponent big.Int

	strLength := len(input)      //The length of the input string.
	s := strconv.Itoa(strLength) //Convert the string length from int to string.
	sbig := new(big.Int)
	sbig.SetString(s, 10) //Convert this into a big.Int.

	for _, c := range input { //For each character in the input string...
		var output = new(big.Int).SetInt64(1)
		exponent = *exponent.Sub(sbig, counter) //Set the exponent to (stringlength) -														 counter, fx. if the string is "abc" the len is 3 and the counter is 1 so the exponent would be 3-1 = 2.

		for exponent.Cmp(z0) == 1 { //If the exponent is not equal to zero...
			output = output.Mul(output, base)       //output = output * 16.
			exponent = *exponent.Sub(&exponent, z1) //exponent = exponent - 1.
		}

		runeval := (int(c) - '0')           //Gets the character aka rune value.
		runevalStr := strconv.Itoa(runeval) //Convert the integer rune value into a string.
		runeValBigInt := new(big.Int)
		runeValBigInt.SetString(runevalStr, 10) //Convert that string into a big.Int.

		if (int(c) - '0') == 49 { //Convert rune values to decimal values.
			runeValBigInt = new(big.Int).SetInt64(10)
		}
		if (int(c) - '0') == 50 {
			runeValBigInt = new(big.Int).SetInt64(11)
		}
		if (int(c) - '0') == 51 {
			runeValBigInt = new(big.Int).SetInt64(12)
		}
		if (int(c) - '0') == 52 {
			runeValBigInt = new(big.Int).SetInt64(13)
		}
		if (int(c) - '0') == 53 {
			runeValBigInt = new(big.Int).SetInt64(14)
		}
		if (int(c) - '0') == 54 {
			runeValBigInt = new(big.Int).SetInt64(15)
		}

		val.Mul(runeValBigInt, output)     //Multiple the converted rune value with the output.
		output = new(big.Int).SetInt64(1)  //Reset the for the next iteration.
		counter = counter.Add(counter, z1) //Increment the counter by one.

		totalval.Add(&totalval, &val) //Add the converted rune value to the totalvalue.
	}
	return totalval //Return the total value.
}

func trimLeftChar(s string, amountToCutOff int) string {
	//*Helper function for the oracle.
	//*Takes an input string s and an integer taht represents the number of characters to be
	//*removed. This function takes a string and trims of a number of the left most characters.
	//*Returns the trimmed string
	for i := range s {
		if i > amountToCutOff {
			return s[i:]
		}
	}
	return s[:0]
}

func trimLeftUntil00(s string) string {
	//*Helper function for oracle and repeatTrimUntil100
	//*Takes as input some string s and trims off the left most character
	//*until it hits a "00"
	//*Returns the trimmed string
	for i := range s {
		if i > 0 {
			return s[i:]
		}
	}
	return s[:0]
}

func repeatTrimUntil00(s string) string {
	//*Helper funtion for the oracle that trims down a given string until it sees a 00.
	//*Takes as input a string.
	//*Return the trimmed string.
	var trimmedString = s
	if !strings.HasPrefix(s, "00") {
		newTrimmedText := trimLeftUntil00(s)
		trimmedString = repeatTrimUntil00(newTrimmedText)
	} else {
		return trimmedString
	}
	return trimmedString
}

func RandomString(j int) string {
	//*Helper function to create a non-zero padding for the message block.
	//*Takes as input some integer value j
	//*Creates a random string containing "abcdef123456789" getting us a non-zero padding string
	//*Returns the padding string.
	rand.Seed(time.Now().UnixNano())
	var letter = []rune("abcdef123456789")
	b := make([]rune, j)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func setUpConstants(n big.Int, d big.Int) {
	publickey = n         //Sets the public key in fields
	oracleKey = d         //Sets the private key in fields
	keyByteLength = k / 8 //Sets the byte length of the key as, k/8

	//Set the rightkeyLength
	keyLength = bigInt2BigFloat2String(publickey)
	keyLengthInt = len(keyLength)

	//Calculate 2B and 3B for the initial interval.
	keyBigInt := new(big.Int)
	keyToString := strconv.Itoa(k)
	keyBigInt.SetString(keyToString, 10)

	//k-16
	var exponentk16 big.Int
	var B big.Int
	exponentk16 = *exponentk16.Sub(keyBigInt, z16) //Calculates k-16

	//B
	B = *B.Exp(z2, &exponentk16, z0) //Calculates B as 2^(k-16) == 2^8*(k-2)
	fmt.Println("Computed  B: " + B.Text(10))

	//2B
	twoB := *twoB.Mul(z2, &B) //Calculates 2B
	fmt.Println("Computed 2B: " + twoB.Text(10))

	//3B
	threeB := *threeB.Mul(z3, &B) //Calculates 3B
	fmt.Println("Computed 3B: " + threeB.Text(10))

	s0 = *s0.Div(&publickey, &threeB) //Calculates the startvalue as n/3B
	initStartValue = s0
	//s0 = s0.Mul(s0, zz10)
	fmt.Println("StartValue:  " + s0.Text(10))
	fmt.Println("")

	threeBMin1 = *threeBMin1.Sub(&threeB, z1) //Calculate 3B-1
}

func setUpInitialInterval() {
	aValuesList = append(aValuesList, twoB)
	bValuesList = append(bValuesList, threeBMin1)
	newA = twoB
	newB = threeBMin1
}

func createRndCipherMessage(n big.Int) big.Int {
	randomMessage = RandomString(k / 4)
	fmt.Println("")
	fmt.Println("New Random Message: " + randomMessage)
	randomInitMessage := HexToDec(randomMessage)
	startRndCipher := Encrypt(randomInitMessage, n)
	return startRndCipher
}

func printQueingOracle() {
	fmt.Println("")
	fmt.Println("########################################################################---QUEING THE ORACLE!---##########################################################################")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
	fmt.Println("*")
}

func bigInt2BigFloat2String(input big.Int) string {
	resuStr := input.String()                                  //Converts the big.Int public key to a string
	resu, _ := new(big.Float).SetPrec(prec).SetString(resuStr) //Converts the string public key to big.Float
	answer := decToHex(*resu)                                  //Converts the public key as big.Float into a hex string.
	return answer
}

func reverse(s string) string {
	//*This method takes a string as input and return it reversed.
	//*This method goes through each rune and reverses the order.
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
