# THIS PROJECT WAS MADE ON LINUX MINT 22.1, USING PYTHON 3.12!! If it fails to compile/run, ensure that you are at least using python 3.12 before reporting errors.
from time import perf_counter
from hashlib import sha512

# Entropy as "defined in physics" seems to be how many states are possible to reach with a given description. Basically...
# (set of all states) x (description) ~> (less states).
# The description acts as a filter, even if it accurately describes phenomena. The process of losing reachable states creates predictability.
# Since having less states leads to higher predictive power, the goal of introducing entropy into a program is to find, or explore, all possible states.
# If done correctly, outputs should be extremely difficult to predict. Very good for random number generators!

# I aim to make this cryptographically secure at some point but as it stands there are some limitations I'm under that makes this impossible.
# Cryptographic security requires irreversibility and careful system design to prevent predictable outputs regardless of intrusion. Software alone can't do that.
# There's more I'm not touching on here and that's because I know there's things I don't know.
# I won't claim security capability... but I will chase the dream despite this one problem.

'''
  Current system I'm designing around to achieve this:

    - Entropy Source (anything I can measure which provably has *some* randomness. It doesn't need to be perfect, but better sources and mixing sources helps)
    - Entropy Pool   (collection of measurements I can use as the "seed" for a PRNG. PRNG is faster *and* more effective than pure measurements of random stuff)
    - PRNG           (function which uses a seed to generate a "random" number. Hashes work really well here, but they tend to be fairly slow. SHISHUA is onto something)

  To ensure maximum unpredictability is preserved my program needs to handle its parts very carefully. It requires:

    - Entropy sources have their correlations and biases tested/distorted. Every source is a measurement of something; they're all correlated by necessity.
    - PRNG output range cannot favor certain outputs. Seed cycling cannot be left unchecked, otherwise the overlap skews frequencies towards certain outputs.
    - Every possible state be reachable. For bit streams, the number of possible states is 2^n. Each one must be reachable with the same frequency as every other state.

  To ensure that this is cryptographically secure where it can be... I need to thoroughly test very specific properties of my outputs. Those properties are:

    - Irreversible PRNG function. I cannot let an output be reconverted into the seed used to generate it. (This does not add entropy, only restructures what's there)
    - Entropy sources and pool cannot be accessible to an intruder. If intruders can access my source, PRNG outputs are trivial to predict using respective software.
    - Outputs from my PRNG cannot contain patterns which give adversaries information about the PRNG or entropy source. Stats tests *help* with this. No guarantees, ever.

  I will likely add to and change this as I make progress.
'''

# End of random bullshit rambling
'''----------------------------------------------------------------------------------------------------------------'''
# Start of fundamental requirements (entropy source, prng algorithm, eventually a hash function)

rounds = 1 # Changes the number of datasets to use during hashing. This *theoretically* leads to stronger destruction of correlations in data. Keeping it low for testing.
''' ^ for this... If I *have* to do this for a data source, it's obviously a flawed data source to some extent. That warrants investigation and probably hashing anyway.
        Honestly, the fact that this still fails runs test at 2048 (smallest output size) even at a 10000 rounds shows that timing entropy fucking sucks.
'''

# Lookup arrays to convert hexadecimal numbers into binary.
charval =  ['0',    '1',    '2',    '3',    '4',    '5',    '6',    '7',    '8',    '9',    'a',    'b',    'c',    'd',    'e',    'f']
convlist = ["0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]

# Actually does the conversion from hexadecimal to binary...
def convToBin(num):
    seed = ""
    for i in range(len(num)):
        val = 0
        while(num[i] != charval[val]):
            val = val + 1
        seed += convlist[val]
    return seed

'''
# I need a *very* large string (5MB at least) to increase TLB Miss Chance... modifying this, too inconsistent! I need to learn how memory access works to make this more effective.
print(f"{'\033[91m'}Making large strings...")
start = perf_counter()

strinSize = 1000 * 1000 * 15 # 1B * 1000 -> KB... * 1000 -> MB... * 10 -> 10MB
strin1 = bytearray(strinSize)
strin2 = bytearray(strinSize)
for i in range(strinSize):
    strin1 += bytearray(charval[i % len(charval)].encode('utf-8'))
    strin2 += bytearray(charval[(i + 1) % len(charval)].encode('utf-8'))
finish = perf_counter() - start
print(f"{'\033[92m'}Done with strings in {'\033[93m'}{finish:.5f}s!")
'''

# This code is what should be modified if I, or you, ever require a better source of "randomness". Got lava lamps and pngs? This function should make that
#   data useable for the rest of the program. I will be using time since I'm locked to one machine with no external sensors.
def entropySource(size):
    if not isinstance(size, int):
        return None
    start = perf_counter()
    #temp1 = strin1[int((start * 1e8) + size) % (strinSize)]
    #temp2 = strin2[int((start * 1e8) - size) % (strinSize)]
    finish = perf_counter() - start
    return int(finish * 1e9)
'''
# This only returns variation in time measurements influenced by: cpu scheduling, temperature throttling, and cache misses.
# Throwing size>0 in there might increase thermal throttling and cache miss probability. For this to be more effective, I need to learn how CPUs try to predict code.
# Entropy here lies in the *total effective range and variance* in recorded times. Messing with *that* distribution destroys entropy.
# That means NO rules that restricts the range and frequency of outputs at this stage.
'''

def genNumber(userInput, length, seed=None): # userInput acts as another source of entropy since it can vary. I will not be changing mine, but you can change yours however you like.
    global rounds
    rnum = ""
    last = 0
    hashval = ""
    if(seed == None):
        while(len(rnum) < int((length / 4) - 1)):
            tempdata = userInput
            for i in range(rounds):
                while(len(tempdata) < 512): # I need to fill up the data structure for sha512. sha512 always fills in holes with the same data. Not allowed.
                    temp = entropySource(last)
                    last = int(temp) # Trying to force cpu to speculate the wrong memory address and miss the correct one. Longer times -> Higher range of outputs ~> good for entropy
                    tempdata += bin(temp)[2:]
                if(len(tempdata) > 512):
                    tempdata = tempdata[:511]
                hashval += tempdata
            hashval = str(sha512(tempdata.encode('utf-8')).hexdigest())
            rnum += hashval # Add new hash value to 'random' number.
            hashval = ""    # Reset hashval for next iteration.
        rnum = convToBin(rnum)
    else:   # Seeded number generation should be repeatable. Not useful for *any* cryptographic purpose, but good practice for me so I don't really care about that here...
        return None
    return rnum[0:length]

# End of fundamental requirements... entropy source (measure time), constant data structure (fix precision + hash), hash function soon...
'''----------------------------------------------------------------------------------------------------------------'''
# Start of global variable declaration and required statistical functions.... please include various randomness tests. i.e runs, appx entropy, monobit, ect

''' I moved all this code into "stats.py". All my tests and analysis code will be present there. '''

# End of statistical functions... dataset generation, predictions, recalcs, and printing state!!
'''----------------------------------------------------------------------------------------------------------------'''
# Start of testing code...

'''
FOR ANYONE INTERESTED IN CRYPTOGRAPHIC SECURITY: DO NOT USE THIS AS IS. I CANNOT STRESS THAT ENOUGH!

https://mzsoltmolnar.github.io/random-bitstream-tester/
^ this is for testing the streams. This program passes all tests *usually* except for runs test which it fails ~60-70% of the time at small bitstream lengths... 20-30% with rounds.
    Probably because I'm sampling entropy from time measurements. Passing tests DOES NOT MEAN cryptographic security. If you need that, then good luck lmao.
    Don't take this lightly... that's all I need from you.
'''

#stop = ""
#while(stop == ""):
start = perf_counter()

nums = 2048
print(f"{'\033[91m'}Generating {nums} bits...")
seed = genNumber("whatisHAPPENING AAAAAAAAA", nums)
print(f"{'\033[95m'}Length:                          {len(seed)}")
print(f"{'\033[94m'}Seed:\n{seed}")

finish = perf_counter() - start
print(f"{'\033[96m'}Generation time: {'\033[91m'}{finish:.5f}s")
#stop = str(input())
