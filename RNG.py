from time import perf_counter
from hashlib import sha512

# Entropy as "defined in physics" seems to be how much information you lose with a chosen description. Basically...
# (set of all states) x (description) -> (less states).
# The description acts as a filter, even if it accurately describes phenomena. The process of losing info is entropy.
# Since information -> inf leads to higher predictive power, the goal of introducing entropy into a program seems to be
#   to create functionality which isn't predictable. Cryptographic security requires irreversibility to prevent predictable outputs without intrusion.

# I aim to make this cryptographically secure at some point but as it stands there are systemic, environmental, and informational limitations
#   I'm under which make this unrealistic. I'll come back to this when I'm better equipped. The above statements will probably change as I learn more stuff.

''' Samples:
                                 0     | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    | 13    | 14    | 15
Global Probabilities per bit:    1.000 | 0.806 | 0.188 | 0.604 | 0.412 | 0.436 | 0.506 | 0.462 | 0.538 | 0.386 | 0.510 | 0.148 | 0.016 | 0.004 | 0.000 | 0.000
Local Probabilities per bit:     1.000 | 1.000 | 0.000 | 0.800 | 0.200 | 0.450 | 0.550 | 0.400 | 0.400 | 0.500 | 0.400 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000
Local stray from Probability:    0.000 | 0.194 |-0.188 | 0.196 |-0.212 | 0.014 | 0.044 |-0.062 |-0.138 | 0.114 |-0.110 |-0.148 |-0.016 |-0.004 | 0.000 | 0.000
Predict-Score for each bit:      0.000 | 0.302 | 0.294 | 0.614 | 0.626 | 0.856 | 0.933 | 0.852 | 0.772 | 0.666 | 0.849 | 0.244 | 0.031 | 0.008 | 0.000 | 0.000
Best score was 0.9331 at bit 6
Elapsed time: 0.00928s
---
                                 0     | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    | 13    | 14    | 15
Global Probabilities per bit:    1.000 | 0.494 | 0.372 | 0.594 | 0.422 | 0.476 | 0.520 | 0.476 | 0.452 | 0.504 | 0.488 | 0.306 | 0.056 | 0.004 | 0.000 | 0.000
Local Probabilities per bit:     1.000 | 0.900 | 0.000 | 0.650 | 0.300 | 0.500 | 0.550 | 0.400 | 0.400 | 0.300 | 0.450 | 0.050 | 0.000 | 0.000 | 0.000 | 0.000
Local stray from Probability:    0.000 | 0.406 |-0.372 | 0.056 |-0.122 | 0.024 | 0.030 |-0.076 |-0.052 |-0.204 |-0.038 |-0.256 |-0.056 |-0.004 | 0.000 | 0.000
Predict-Score for each bit:      0.000 | 0.583 | 0.459 | 0.755 | 0.720 | 0.923 | 0.923 | 0.862 | 0.845 | 0.761 | 0.929 | 0.439 | 0.104 | 0.008 | 0.000 | 0.000
Best score was 0.9290 at bit 10
Elapsed time: 0.00930s
---
                                 0     | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    | 13    | 14    | 15
Global Probabilities per bit:    1.000 | 0.946 | 0.038 | 0.654 | 0.372 | 0.438 | 0.474 | 0.466 | 0.498 | 0.364 | 0.578 | 0.040 | 0.016 | 0.002 | 0.000 | 0.000
Local Probabilities per bit:     1.000 | 0.900 | 0.050 | 0.700 | 0.250 | 0.400 | 0.250 | 0.400 | 0.650 | 0.250 | 0.650 | 0.050 | 0.050 | 0.000 | 0.000 | 0.000
Local stray from Probability:    0.000 |-0.046 | 0.012 | 0.046 |-0.122 |-0.038 |-0.224 |-0.066 | 0.152 |-0.114 | 0.072 | 0.010 | 0.034 |-0.002 | 0.000 | 0.000
Predict-Score for each bit:      0.000 | 0.102 | 0.075 | 0.652 | 0.635 | 0.834 | 0.709 | 0.855 | 0.817 | 0.628 | 0.769 | 0.079 | 0.031 | 0.004 | 0.000 | 0.000
Best score was 0.8554 at bit 7
Elapsed time: 0.01001s

--------------------------------
# PUNISH BAD PROBABILITIES WHAT IS THIS?!? Also learn to build equations you incompetent fool.
Global Distribution:--------------------------------------------------------------------------------------------
                                 0     | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10    | 11    | 12    | 13    | 14    | 15
Global Probabilities per bit:    1.000 | 0.556 | 0.610 | 0.556 | 0.513 | 0.515 | 0.566 | 0.434 | 0.384 | 0.296 | 0.090 | 0.011 | 0.003 | 0.000 | 0.000 | 0.000
Local Probabilities per bit:     1.000 | 0.120 | 0.720 | 0.440 | 0.400 | 0.440 | 0.320 | 0.480 | 0.440 | 0.320 | 0.280 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000
Local stray from Probability:    0.000 |-0.436 | 0.110 |-0.116 |-0.113 |-0.075 |-0.246 | 0.046 | 0.056 | 0.024 | 0.190 |-0.011 |-0.003 |-0.000 |-0.000 | 0.000
Predict-Score for each bit:      0.000 | 0.012 | 0.263 | 0.280 | 0.319 | 0.461 | 0.076 | 0.550 | 0.441 | 0.467 | 0.028 | 0.020 | 0.006 | 0.001 | 0.000 | 0.000
Best score was 0.550 at bit 7
Local Distribution: --------------------------------------------------------------------------------------------
Batch Probability:               0.300
Sample Probability:              0.280
Sample Stray from Probability:  -0.020
Batch Unpredictability Score:    0.492
RETRIES:                         2114
Seed:
10000110000010000001001100000001100000001100111101
Elapsed time: 3.53468s

--------------------------------
Global Distribution:--------------------------------------------------------------------------------------------------
                                 0     | 1     | 2     | 3     | 4     | 5     | 6     | 7     | 8     | 9     | 10
Global Probabilities per bit:    0.010 | 0.000 | 0.010 | 0.030 | 0.360 | 0.710 | 0.570 | 0.560 | 0.590 | 0.530 | 0.500
Recent Probabilities per bit:    0.000 | 0.000 | 0.000 | 0.000 | 0.300 | 0.700 | 0.700 | 0.400 | 0.600 | 0.400 | 0.500
Prediction Accuracies:           0.990 | 1.000 | 1.000 | 0.990 | 0.667 | 0.657 | 0.594 | 0.477 | 0.493 | 0.507 | 0.455
Entropy Scores:                  0.014 | 0.000 | 0.000 | 0.014 | 0.587 | 0.609 | 0.754 | 0.937 | 0.980 | 0.981 | 0.879
Highest Score was 0.981 at bit 9
Local Distribution: --------------------------------------------------------------------------------------------------
Batch Probability:               0.477
Recent Probability:              0.500
Sample Prediction Accuracy:      0.510
Batch Entropy Score:             0.974
Length:                          944
Seed:
0000101011000000101001100100010001111010100001110011001011101000001100001011000101001001100001010100010100001101000000
0100001001101111000000101100001011000001111001000011101001000111001001011010011110010000101110100110011011011010011111
1111010100100101101111110001101111010011100010011001101000100111011110000000000101101001100010000110101111010000000000
0100101111100011000100011000111010000011000010110110111111100010001010111011101000100011011100110101000100100110001011
0000010001000110001000000101110110100011110101010100000100010100110011101001111101110100100111111101011100111000000011
0101101111000101110001111000110011110001100110011101100000100011100110010110100000100101000001110111100000111011000101
0110111001110100010101011101110011000110001001110101100111100010010011010111100110110100100110100110000101000001100010
0110101110101011000111110011011111101100011111101010100111010000110110000111001001110011110101111001010011011110000011
'''

# End of random bullshit rambling
'''----------------------------------------------------------------------------------------------------------------'''
# Start of fundamental requirements (entropy source, reliable data)

# Convert hexadecimal hashes to binary representation...
charval = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
convlist = []
for i in range(16):
    temp = bin(i)
    temp = temp[2:]
    for j in range(4 - len(temp)):
        temp = f"0{temp}"
    convlist.append(temp)


strinSize = 1024 * 5
strin1 = ""
strin2 = ""
for i in range(strinSize): # I need a ridiculously large string (5MB at least) to increase TLB Miss chance...
    strin1 = f"{strin1}{charval[i % len(charval)]}"
    strin2 = f"{strin2}{charval[(i + 1) % len(charval)]}"

# This only returns variation in time for cpu scheduling, temperature throttling, and cache miss computation time.
# Throwing size>0 in there starts measuring cache misses and increases the room for thermal throttling and cache miss "probability". More sources!!
# Entropy here lies in the RANGE AND VARIANCE in recorded times. Equations and "predictability filtering" across time both destroy entropy.
# That means NO rules that restricts the range and frequency of outputs. Obviously do check for "randomness" but the enforcement of rules causes problems. Weird...
# This is a delicate problem, stay vigilant!!
def measureTime(size):
    if not isinstance(size, int):
        return None
    start = perf_counter()
    #temp = 5 + 7   # Removing line in favor of the below method... below is more difficult for teh CPU to maintain, but it's pretty terrible I'll be honest.
    temp = strin1[int((start * 1e10) + size) % (strinSize)]
    temp = strin2[int((start * 1e10) - size) % (strinSize)]
    finish = perf_counter() - start
    return int(finish * 1e8)

def fixPrecision(num, digits):  # Fixing precision is bad, limits data range. Limits are bad for entropy. Fix this please.
    if isinstance(num, float) and isinstance(digits, int):
        value = bin(num)
    elif isinstance(num, int) and isinstance(digits, int):
        value = bin(num)
    else:
        return None # Please pass the correct data types

    temp = value[2:]

    if(digits == 0):
        return int(temp)

    difference = len(temp) - digits
    if (difference > 0):
        for i in range(difference):
            temp = temp[:-1]
    elif (difference < 0):
        for i in range(abs(difference)):
            temp = "0" + temp
    else:
        return temp
    return temp

def convToBin(num):
    # Just gonna trust that I'm never gonna use this function outside of genNumber. Nobody else is using this program... Nobody in cybersec better use this...
    seed = ""
    for i in range(len(num)):
        val = 0
        while(num[i] != charval[val]):
            val = val + 1
        seed = f"{seed}{convlist[val]}"
    return seed

def genNumber(userInput, length): # userInput makes this stronger, but doesn't mean csprng. Tragic.
    rnum = ""
    limit = length * 4
    size = 1
    while(size < length):   # Trying to speed up this function by running the below loop as many times as it takes to generate a long enough bitstream.
        size = size * 512

    last = 0
    while(len(rnum) < limit):
        hashval = ""
        for i in range(10):
            temp = measureTime(last)
            time = fixPrecision(temp, 11)
            hashval = hashval + time
            last = int(time)
        hashval = f"{userInput}{hashval}"
        hashval = str(sha512(hashval.encode('utf-8')).hexdigest())
        rnum = f"{rnum}{hashval}"
    rnum = convToBin(rnum)
    return rnum[0:length]

# End of fundamental requirements... entropy source (measure time), constant data structure (fix precision + hash), hash function soon...
'''----------------------------------------------------------------------------------------------------------------'''
# Start of global variable declaration and required statistical functions.... please include various randomness tests. i.e runs, appx entropy, monobit, ect

values = []             # Stores local distribution.
localdist = 10          # Size of the locally maintained dist... keep this somewhat low, please.
globldist = 0           # Size of global dataset (whole dist not maintained for memory reasons)

gprb = []   # Global Average
lprb = []   # Local Probability
pacc = []   # Global Prediction Accuracy
escore = [] # Global Predictability Score

# The following functions should provide information on which bits are the most unpredictable.
def predictBit(number, bit, globalfavor, localfavor): # Should get a prediction accuracy score very close to min entropy. Actually predict, don't *just* use min entropy.
    favoring = globalfavor + localfavor # Negative number means favoring 0s, Positive number means favoring 1s
    if(favoring < 0 and str(number)[bit] != "0"):
        return False
    elif(favoring >= 0 and str(number)[bit] != "1"):
        return False
    else:
        return True

def predictBits(number):
    global pacc
    for i in range(len(str(number))): # Should have an item for each bit
        accurate = predictBit(number, i, (gprb[i] - 0.5), (lprb[i] - 0.5))
        if(accurate == True):
            pacc[i] = ((pacc[i] * (globldist - 1)) + 1) / globldist
        else:
            pacc[i] = (pacc[i] * (globldist - 1)) / globldist

def genScores(): # Effectively ranks which bits defy prediction. Perfect defiance is predictable, so the ideal is ~50% defiance.
    global escore
    escore = []
    for i in range(len(pacc)):  # For every bit...
        score = pow(2, (1 - (abs(pacc[i] - 0.5) * 2))) - 1
        escore.append(score)      # If a sequence is +-2% then assume failing. Not sure if this is particularly useful anywhere else though.

def recalculateStats(measurement):
    global globldist
    global localdist
    global values
    global gprb
    global lprb
    global pacc
    predictBits(measurement)
    for i in range(len(str(measurement)) - 1):   # For each digit in number...
        gprb[i] = ((gprb[i] * globldist) + int(str(measurement)[i])) / (globldist + 1)        # Recalc global average
        if(str(values[0])[i] == '0'):
            lprb[i] = (((lprb[i]) * len(values)) + int(str(measurement)[i])) / len(values)    # Recalc local average when oldest number was 0
        else:
            lprb[i] = (((lprb[i]) * len(values)) + int(str(measurement)[i]) - 1) / len(values)# Recalc local average when oldest number was 1
    genScores()                 # Recalculate scores
    values.pop(0)               # Delete oldest local number
    values.append(measurement)  # Add newly passed number to local dataset
    globldist = globldist + 1   # Reflect growth of global dataset

def genDataset(size):
    global globldist
    global localdist
    global gprb
    global lprb
    global pacc
    global values

    # Calculate stats up to the localdist size. Calculation is slighly different until the localdist size has been reached.
    for i in range(localdist):
        temp = measureTime(0)
        #print(f"{temp}")
        num = fixPrecision(temp, 11)  # Generate "random" number by measuring time, then fix precision to 16-Bit Binary.
        values.append(num)
        globldist = globldist + 1
        if(i == 0):     # Initialization of list and assume worst case prediction for first generated value.
            for i in range(len(values[0])):
                gprb.append(float(int(values[0][i])))
                lprb.append(gprb[i])
                pacc.append(1.0)
        else:           # Values afterwards are calculated with rolling average formulas while localprobs are set to equal globalprobs... (size hasn't been reached)
            for i in range(len(values[0])):
                predictBits(values[len(values) - 1])    # This function automatically adjusts prediction accuracies once initialized, regardless of localdist size
                if(values[len(values) - 1][i] == "1"):
                    gprb[i] = (gprb[i] * (globldist - 1) + 1) / globldist
                else:
                    gprb[i] = (gprb[i] * (globldist - 1)) / globldist
                lprb[i] = gprb[i]

    for i in range(size - localdist):
        num = fixPrecision(measureTime(0), 11)
        recalculateStats(num)                       # This function handles all stats adjustments from here on.

def printData():    # I'm setting this up to print stats into a format which is easy to read and color coded.
    labelpadding = 33
    strin = ""  # This lien is for labelling all the bits representing my time values.
    while(len(strin) < labelpadding): # Add spaces until time values are outputted next line, structures output nicely.
        strin = f"{strin} "
    for i in range(len(gprb)):
        tempstr = f"{i}" # Increments i so it counts from 1 to whatever number I find to be most relevant.
        while(len(tempstr) < 6):
            tempstr = f"{tempstr} "
        tempstr = f"{tempstr}| "
        strin = f"{strin}{tempstr}"
    print(f"{strin[:-3]}") # I remove the last three because on the last iteration I have extra chars that aren't necessary.
    # Time to repeat the above process for all my data values labelled accordingly...

    strin = "Global Probabilities per bit:"
    while(len(strin) < labelpadding):
        strin = f"{strin} "
    for i in range(len(gprb)):
        temp = gprb[i]
        strin = f"{strin}{temp:.3f} | "
    print(f"{'\033[92m'}{strin[:-3]}")

    strin = "Recent Probabilities per bit:"
    while(len(strin) < labelpadding):
        strin = f"{strin} "
    for i in range(len(lprb)):
        temp = lprb[i]
        strin = f"{strin}{temp:.3f} | "
    print(f"{'\033[96m'}{strin[:-3]}")

    strin = "Prediction Accuracies:"
    while(len(strin) < labelpadding):
        strin = f"{strin} "
    for i in range(len(pacc)):
        temp = pacc[i]
        strin = f"{strin}{temp:.3f} | "
    print(f"{'\033[91m'}{strin[:-3]}")

    strin = "Entropy Scores:"
    while(len(strin) < labelpadding):
        strin = f"{strin} "
    for i in range(len(escore)):
        temp = escore[i]
        strin = f"{strin}{temp:.3f} | "
    print(f"{'\033[94m'}{strin[:-3]}")

    setbest = -1.0
    setpos = 0
    for i in range(len(pacc)): # Find best score
        if (escore[i] > setbest):
            setbest = escore[i]
            setpos = i
    print(f"{'\033[93m'}Highest Score was {'\033[95m'}{setbest:.3f}{'\033[93m'} at bit {'\033[95m'}{setpos}")

def printStats(seed):
    num = str(seed) # Fix data type for stats analysis and set up inital stats
    batchprob = int(num[0])
    recentprob = batchprob
    lacc = 1.0      # Assume worst case prediction...
    lscore = 0.0
    for i in range(1, (len(num) - 1)): # Have to skip first iteration since I set them up prior.
        accurate = predictBit(num, i, (batchprob - 0.5), (recentprob - 0.5))
        if (accurate == True):
            lacc = ((lacc * (i - 1)) + 1) / i
        else:
            lacc = (lacc * (i - 1)) / i

        # "Global" seed stats recalc
        if(seed[i] == "1"):
            batchprob = (batchprob * (i - 1) + 1) / i
        else:
            batchprob = (batchprob * (i - 1)) / i

        # "Local" seed stats recalc. Checks localdist variable for size limit and calculates off that.
        if(i <= localdist):
            recentprob = batchprob
        else:
            if(seed[i - localdist] == "0"):
                recentprob = ((recentprob * localdist) + int(seed[i])) / localdist
            else:
                recentprob = ((recentprob * localdist) + int(seed[i]) - 1) / localdist
    # Entropy score for the given seed.
    lscore = pow(2, (1 - (abs(lacc - 0.5) * 2))) - 1 # This function might not match the global score formula!! It should though.

    print(f"{'\033[95m'}Local Distribution: {'\033[93m'}--------------------------------------------------------------------------------------------------")
    print(f"{'\033[92m'}Batch Probability:               {batchprob:.3f}")
    print(f"{'\033[96m'}Recent Probability:              {recentprob:.3f}")
    print(f"{'\033[91m'}Sample Prediction Accuracy:      {lacc:.3f}")
    print(f"{'\033[94m'}Batch Entropy Score:             {lscore:.3f}")
    return [batchprob, recentprob, lacc, lscore]

# End of statistical functions... dataset generation, predictions, recalcs, and printing state!!
'''----------------------------------------------------------------------------------------------------------------'''
# Start of testing code...

'''
FOR ANYONE INTERESTED IN CRYPTOGRAPHIC SECURITY:

https://mzsoltmolnar.github.io/random-bitstream-tester/
^ this is for testing the streams. This program passes all tests *usually* except for runs test which it fails ~60-70% of the time. Probably because I'm
    sampling entropy from time measurements. Passing tests DOES NOT MEAN cryptographic security. If you need that, use the OS RNG. Please.
    Either that or measure some quantum states. That's the closest there is to actual random events in the universe. There's more nuance, but
    don't take this lightly... that's all I need from you.
'''

start = perf_counter()

genDataset(localdist * 10)
print(f"{'\033[95m'}Global Distribution:{'\033[93m'}--------------------------------------------------------------------------------------------------")
printData()

nums = 118 * 8  # Terminal width on my setup is 118. I set up my stats and printing to match that so it's easy to read. Different window sizes mess that up lol.
seed = genNumber("whatisHAPPENING AAAAAAAAA", nums)
printStats(seed)
print(f"{'\033[95m'}Length:                          {len(seed)}")
print(f"{'\033[93m'}Seed:\n{seed}")

finish = perf_counter() - start
print(f"{'\033[96m'}Elapsed time: {'\033[91m'}{finish:.5f}s")
