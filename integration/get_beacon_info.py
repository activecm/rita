import json
import os
import glob
import gzip
import re
import math
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
from scipy import stats


#dnscat2
# src= '10.55.200.11'
# dst='205.251.197.77'

# src='10.136.0.18'
# dst='171.161.198.100'
# dst=''
# fqdn='www.honestimnotevil.com'

src='10.55.100.103'
dst=''
fqdn='www.bankofamerica.com'


logType='tsv'

# src='10.55.100.109'
# fqdn='www.alexa.com'
# dst='165.227.216.194'

# path = './test_data/proxy'
path = '/Users/lisa/Desktop/go_ws/rita-v2/test_data/valid_tsv'
# path = '/home/parallels/Desktop/chris/dnscat2-ja3-strobe-agent'
order = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','agent_hostname','agent_uuid']
# size = 'multiple'
size = 'single'

connOrder = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','agent_hostname','agent_uuid']
httpOrder = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','trans_depth','method','host','uri','referrer','version','user_agent','request_body_len','response_body_len','status_code','status_msg','info_code','info_msg','tags','username','password','proxied','orig_fuids','orig_filenames','orig_mime_types','resp_fuids','resp_filenames','resp_mime_types']
sslOrder = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','version','cipher','curve','server_name','resumed','last_alert','next_protocol','established','cert_chain_fuids','client_cert_chain_fuids','subject','issuer','client_subject','client_issuer','validation_status','ja3','ja3s']


pattern = dst


bimodalBucketSize = 0.05
bimodalOutlierRemoval = 1
bimodalMinHours = 11
durMinHours = 6
consistencyIdealHours = 12
histModeSensitivity = 0.05

def main():
    # validate combinations of src / dst/ fqdn variables
    if src == "":
        print("src IP not defined")
    if src != "" and dst != "" and fqdn != "":
        print("src IP, dst IP, and FQDN cannot all be defined, supply either IP beacon or SNI beacon")
    if dst == "" and fqdn == "":
        print("please define either dst IP or FQDN")

    # run beacon analysis
    if dst != "":
        tsData, dsData, minTsStartOfHour, minTs, maxTs = getIPBeacon()
        analyze(tsData, dsData, minTsStartOfHour, minTs, maxTs)
    else:
        tsData, dsData, minTsStartOfHour, minTs, maxTs = getSNIBeacon()
        analyze(tsData, dsData, minTsStartOfHour, minTs, maxTs)

# get IP beacons from conn.log
def getIPBeacon():
    minTsStartOfHour, minTs, maxTs, uids = getConnData()

    tsData = []
    dsData = []
    # filter conn records by src, dst, and min timestamp
    for uid in uids:
        entry = uids[uid]
 
        # we filter by minTsStartOfHour instead of minTs because the data is stored in hour buckets aligned to the start of the hour
        if entry['src']==src and entry['dst']==dst and entry['ts'] >= minTsStartOfHour:
            tsData.append(entry['ts'])
            dsData.append(entry['ds'])

    return tsData, dsData, minTsStartOfHour, minTs, maxTs



# read log files line by line
def read_lines(filename, headerOrder=None):
    print("reading:", filename)
    def read_tsv_line(line, headerOrder):
        # limit the number of lines returned to ones that match the source address
        if re.search(src, line):
            details = line.split("\t")
            # split items by tab character based on the header order for this tsv file
            details = [x.strip() for x in details]
            structure = {key:value for key, value in zip(headerOrder, details)}
            if structure['ts'] != '#close':
                return structure
            
            
    # read gzipped logs
    if filename.endswith('.gz'):
        with gzip.open(filename, 'rt', encoding='UTF-8') as f:
            # read logs line by line as json
            if logType == "json":
                for line in f:
                    yield json.loads(line)
            else:
                # read logs line by line from tsv, automatically skipping the header
                for i in range(8):
                    next(f)
                for line in f.readlines():
                    d = read_tsv_line(line, headerOrder)
                    if d is not None:
                        yield d
                
    else:
        # read uncompressed logs
        with open(filename, "r") as f:
            # read logs line by line as json
            if logType == "json":
                for line in f:
                    yield json.loads(line)
            else:
                # read logs line by line from tsv, automatically skipping the header
                for i in range(8):
                    next(f)
                for line in f:
                    d = read_tsv_line(line, headerOrder)
                    if d is not None:
                        yield d
               
           
               

# read UIDs for either the HTTP or SSL files
def readSNIFile(file_names, headerOrderList, fqdnField, uids, dsData, tsData, minTsStartOfHour):
    for filename in file_names:
        for line in read_lines(filename, headerOrder=headerOrderList):
            try:
                if line['id.orig_h']==src and line[fqdnField]==fqdn:
                    # check if the SNI record has a matching conn record, and check to see if it has been used before
                    # we only include the timestamp/byte once per zeek uid
                    if line['uid'] in uids and uids[line['uid']]['used'] == False:
                            uids[line['uid']]['used'] = True
                            # we filter by minTsStartOfHour instead of minTs because the data is stored in hour buckets aligned to the start of the hour
                            if uids[line['uid']]['ts'] >= minTsStartOfHour:
                                dsData.append(uids[line['uid']]['ds'])
                                tsData.append(uids[line['uid']]['ts'])
            except KeyError: 
                pass

# get SNI beacon data from http.log, ssl.log, and conn.log
def getSNIBeacon():
    tsData = []
    dsData = []

    if size == 'single':
        # get min/max timestamp data and the UIDs seen in the conn logs
        # this is done in one step so that we don't need to read the conn logs twice
        minTsStartOfHour, minTs, maxTs, uids = getConnData()

        httpFiles = glob.glob(os.path.join(path, "http*.log"))
        httpFiles.extend(glob.glob(os.path.join(path, "http*.log.gz")))
        readSNIFile(httpFiles, httpOrder, "host", uids, dsData, tsData, minTsStartOfHour)

        sslFiles = glob.glob(os.path.join(path, "ssl*.log"))
        sslFiles.extend(glob.glob(os.path.join(path, "ssl*.log.gz")))
        readSNIFile(sslFiles, sslOrder, "server_name", uids, dsData, tsData, minTsStartOfHour)
       
    return tsData, dsData, minTsStartOfHour, minTs, maxTs

def analyze(tsData, dsData, minTsStartOfHour, minTs, maxTs):
    if len(tsData) == 0 or len(dsData) == 0:
        print("could not find connection pair in logs, are you sure you're looking at the right dataset?")
        exit(0)
    start = minTs
    end = maxTs
     
    tsLength = len(tsData) - 1
    print(("connection count:").rjust(20), len(tsData))
    print(("tsLength:").rjust(20), tsLength)
    
    # sort data
    sortedTsData = sorted(tsData, key=float)
    sortedDsData = sorted(dsData, key=int)

    # print(sortedData)
    dsSizes, dsCounts, dsMode, dsModeCount= calculateDistinctCounts(dsData)

    # get TS Score
    tsScore, tsSkew, tsMadm = getTsScore(sortedTsData, tsLength)
    dsScore, dsSkew, dsMadm = getDsScore(sortedDsData, dsMode)
    print(("TS SCORE:").rjust(20), tsScore)
    print(("DS SCORE:").rjust(20), dsScore)


    # get histogram score
    bucketDivs, freqList, freqCount, totalBars, longestRun, histScore = getTsHistogramScore(start, end, sortedTsData)
    coverage, consistency, durScore = getDurationScore(start, end, int(tsData[0]), int(tsData[len(tsData)-1]), totalBars, longestRun)
    print(("HIST SCORE:").rjust(20), histScore)
    print(("DUR SCORE:").rjust(20), durScore)

    score = np.round(((tsScore*0.25)+ \
                       (dsScore*0.25)+ \
                       (durScore*0.25)+ \
                       (histScore*0.25)) * 1000) / 1000
    print(("THE SCORE:").rjust(20), score)

    # plot
    plotHistogram(sortedTsData, start, end)


def getDurationScore(dmin, dmax, histMin, histMax, totalBars, longestConsecutiveRun):
    if durMinHours < 1 or consistencyIdealHours < 1:
        print("invalid duration score thresholds")
        exit(1)

    if durMinHours < 1:
        print("bimodalMinHours is invalid")
        exit(1)

    if consistencyIdealHours < 1:
        print("consistencyIdealHours is invalid")
        exit(1)

    if dmax <= dmin:
        print("max is less than or equal to min")
        exit(1)

    if histMax <= histMin:
        print("hist max is less than or equal to hist min")
        exit(1)
    
    coverage, consistency, score = 0, 0, 0
    if totalBars >= durMinHours:

        coverage = math.ceil(((histMax - histMin) / (dmax - dmin))*1000)  / 1000
        if coverage > 1:
            coverage = 1

        consistency = math.ceil((longestConsecutiveRun / consistencyIdealHours) * 1000) / 1000
        if consistency > 1:
            consistency = 1

        score = max(coverage, consistency)
    return coverage, consistency, score

def getDsScore(data, mode):
    dsSkew, dsSkewScore = calculateBowleySkewness(data)

    dsMadm, dsMadmScore = calculateMedianAbsoluteDeviation(data, 0)

    # dsSmallnessScore = max(1 - mode / 65535, 0)

    dsScore = np.round((((dsSkewScore+dsMadmScore)/2.0)*1000)) / 1000

    return dsScore, dsSkew, dsMadm

def getTsHistogramScore(start, end, sortedData):
    # get bucket list
    # we currently look at a 24 hour period
    bucketDivs = createBuckets(start, end, 24)

    # use timestamps to get freqencies for buckets
    freqList, freqCount, totalBars, longestRun = createHistogram(bucketDivs, sortedData)

    print(("hist bucket divs:").rjust(20), bucketDivs)
    print(("hist freq list:").rjust(20), freqList)
    print(("hist freq count:").rjust(20), freqCount)
   
    #  calculate first potential score: coefficient of variation
	#  coefficient of variation will help score histograms that have jitter in the number of
	#  connections but where the overall graph would still look relatively flat and consistent
	#  calculate coefficient of variation score
    cvScore = calculateCoefficientOfVariationScore(freqList)
   
    bimodalFitScore = calculateBimodalFitScore(freqCount, totalBars)
    
    return bucketDivs, freqList, freqCount, totalBars, longestRun, max(cvScore, bimodalFitScore)
   
def calculateCoefficientOfVariationScore(freqList):
    total = 0

    for e in freqList:
        total += e

    freqMean = total / len(freqList)

    sd = float(0)

    for j in range(0,len(freqList),1):
        sd += math.pow(freqList[j] - freqMean, 2)
    
    sd = np.sqrt(sd / len(freqList))
   
    cv = sd / np.abs(freqMean)

    cvScore = float(0)
    if cv > 1:
        cvScore = 0
    else:
        cvScore = np.round((1-cv)*1000) / 1000
    
    # cvScore = np.ceil((1 - cv)*1000) / 1000
    if cvScore > 1:
        cvScore = 1
    return cvScore

def calculateBimodalFitScore(freqCount, totalBars):
    bimodalFit = 0

    if totalBars >= bimodalMinHours:
        largest = 0
        secondLargest = 0

        for key, val in freqCount.items():
            if val > largest:
                secondLargest = largest
                largest = val
            elif val > secondLargest:
                secondLargest = val
            
        bimodalFit = (largest + secondLargest) / max(totalBars-bimodalOutlierRemoval, 1)
   
    bimodalFitScore = np.ceil(bimodalFit * 1000) / 1000
    if bimodalFitScore > 1:
        bimodalFitScore = 1
    return bimodalFitScore


# createBuckets
def createBuckets(start, stop, size):
    # Set number of dividers. Since the dividers include the endpoints,
    # number of dividers will be one more than the number of desired buckets
    total = size + 1

    # declare list
    bucketDivs = [None]*(total)#make([]int64, total)

    # calculate step size
    step = math.floor((math.floor(stop) - math.floor(start)) / (total - 1))

    # set first bucket value to min timestamp
    bucketDivs[0] = start

    # create evenly spaced timestamp buckets
    for i in range(1,total,1):
    # for i := int64(1); i < total; i++ 
        bucketDivs[i] = start + (i * step)


    # set first bucket value to max timestamp
    bucketDivs[total-1] = math.floor(stop)

    return bucketDivs

# createHistogram
def createHistogram(bucketDivs, sortedData):
    i = 0
    bucket = bucketDivs[i+1]
    # calculate the number of connections that occurred within the time span represented
    # by each bucket
    freqList = [0]*(len(bucketDivs)-1)#make([]int, len(bucketDivs)-1)

    # loop over sorted timestamp list
    for entry in sortedData:
        # increment if still in the current bucket
        if entry < bucket:
            freqList[i]+=1
            continue

        # find the next bucket this value will fall under
        for j in range(i+1,len(bucketDivs)-1,1):
        # for j := i + 1; j < len(bucketDivs)-1; j++ {
            if entry < bucketDivs[j+1]:
                i = j
                bucket = bucketDivs[j+1]
                break


        # increment count
        # this will also capture and increment for a situation where the final timestamp is
        # equal to the final bucket
        freqList[i]+=1

    freqCount, totalBars, longestRun = getFrequencyCounts(freqList)
    return freqList, freqCount, totalBars, longestRun


def getFrequencyCounts(freqList):
    # make a fequency count map to track how often each value in freqList appears
    largestConnCount = 0
    totalBars = 0

    for item in freqList:
        if item > 0:
            totalBars+=1

        if item > largestConnCount:
            largestConnCount = item
       
            
    freqCount = {}
    bucketSize = np.ceil(largestConnCount * histModeSensitivity)

    freqListLen = len(freqList)
    longestRun = 0
    currentRun = 0

    for i in range(0, freqListLen*2, 1):
        item = freqList[i%freqListLen]

        if item > 0:
            currentRun+=1
        else:
            if currentRun > longestRun:
                longestRun = currentRun
            currentRun = 0
        
        if i < freqListLen:
            if item > 0:
                bucket = int(np.floor(item/bucketSize)*bucketSize)

                if bucket in freqCount:
                    freqCount[bucket]+=1
                else:
                    freqCount[bucket] = 1
    
    if currentRun > longestRun:
        longestRun = currentRun

    if longestRun > freqListLen:
        longestRun = freqListLen
    return freqCount, totalBars, longestRun


def calculateBowleySkewness(data):
    inputLength = len(data)
    if inputLength == 0:
        print("input length for calculating quartiles is 0")
        exit(1)
    
    cutoff1, cutoff2 = 0, 0

    if inputLength % 2 == 0:
        cutoff1 = int(inputLength / 2)
        cutoff2 = int(inputLength / 2)
    else:
        cutoff1 = int((inputLength - 1) / 2)
        cutoff2 = cutoff1 + 1

    q1 = np.median(sorted(data[0:cutoff1]))
    q2 = np.median(sorted(data))
    q3 = np.median(sorted(data[cutoff2:]))

    print("quartiles", q1, q2, q3)
    
    num = q1 + q3 - (2 * q2)

    print("num", num)

    den = q3 - q1

    print("den", den)

    skewness = 0

    if den >= 10 and q2 != q1 and q2 != q3:
        skewness = num / den

    print("SKKKEWWWNEESSS", skewness)

    score = 1 - np.abs(skewness)

    print("skwwwwe score", score)
    

    return skewness, score
    

def calculateMedianAbsoluteDeviation(data, defaultScore):

    if len(data) == 0:
        print("input slice for madm must not be empty")
        exit(1)

    dataSorted = sorted(data)

    median = np.median(dataSorted)

    deviations = [None] * len(dataSorted)

    for key, val in enumerate(dataSorted):
        deviations[key] = np.abs(val - median)

    mad = np.median(deviations)

    score = defaultScore
    if median >= 1:
        score = (median - mad) / median

    if score < 0 or math.isnan(score):
        score = 0

    return mad, score




def getTsScore(sortedData, tsLength):

    #find the delta times between the timestamps
    deltaTimesFull = [None] * (len(sortedData) - 1)

    for i in range(tsLength):
        tempdiff = int(sortedData[i+1]) - int(sortedData[i])
        deltaTimesFull[i] = float(tempdiff)
        # if tempdiff != 0:
        #     diff.append(tempdiff)

    deltaTimesFull = sorted(deltaTimesFull)

    # print(diff)
 # get a list of the intervals found in the data,
    # the number of times the interval was found,
    # and the most occurring interval
    intervals, intervalCounts, tsMode, tsModeCount = calculateDistinctCounts(deltaTimesFull)
   
    nonZeroIndex = 0
 
    for i in range(0,len(deltaTimesFull),1):
        if deltaTimesFull[i] > 0:
            nonZeroIndex = i
            break
    
    deltaTimes = deltaTimesFull[nonZeroIndex:]

    tsSkew, tsSkewScore = calculateBowleySkewness(deltaTimes)
    
    tsMadm, tsMadmScore = calculateMedianAbsoluteDeviation(deltaTimes, 1)
   
    tsScore = np.ceil(((tsSkewScore+tsMadmScore)/2)*1000) / 1000
    # diffLength = len(deltaTimesFull)
    # # Store the range for human analysis
    # tsIntervalRange = deltaTimesFull[diffLength - 1] - deltaTimesFull[0]

   

    print(("ts intervals:").rjust(20), intervals)
    print(("ts interval counts:").rjust(20), intervalCounts)
    # print(("ts interval range:").rjust(20), tsIntervalRange)
    print(("ts mode:").rjust(20), tsMode)
    print(("ts mode count:").rjust(20), tsModeCount)
    print(("ts range:").rjust(20), deltaTimes[len(deltaTimes) - 1] - deltaTimes[0] )

    return tsScore, tsSkew, tsMadm

# createCountMap returns a distinct data array, data count array, the mode,
# and the number of times the mode occurred
def calculateDistinctCounts(sortedIn):
    if len(sortedIn) < 2:
        print("not enough items in sorted data to calculate distinct counts")
        exit(1)

    sortedIn = sorted(sortedIn)

    distinctNumbers = []
    countsMap = {}

    lastNumber = sortedIn[0]
    distinctNumbers.append(lastNumber)
    if lastNumber in countsMap:
        countsMap[lastNumber]+=1
    else:
        countsMap[lastNumber] = 1


    for currentNumber in sortedIn[1:]:
        if lastNumber != currentNumber:
            distinctNumbers.append(currentNumber)
        
        if currentNumber in countsMap:
            countsMap[currentNumber]+=1
        else:
            countsMap[currentNumber] = 1
        lastNumber = currentNumber
    
    countsArray = [None] * len(distinctNumbers)
    mode = distinctNumbers[0]
    maxCount = countsMap[mode]


    for i, number in enumerate(distinctNumbers):
        count = countsMap[number]
        countsArray[i] = count

        if count > maxCount:
            maxCount = count
            mode = number
        
    return distinctNumbers, countsArray, mode, maxCount

def getConnData():
    uids = {}
    maxTs = 0
    g = glob.glob(os.path.join(path, "conn*.log.gz"))
    g.extend(glob.glob(os.path.join(path, "conn*.log")))
    allConnIshFiles = set(g)
    gn = glob.glob(os.path.join(path, "conn*summary*.log.gz"))
    gn.extend(glob.glob(os.path.join(path, "conn*summary*.log")))
    notRealConnFiles = set(gn)
    connFiles = allConnIshFiles - notRealConnFiles
    for filename in connFiles:
        for line in read_lines(filename, connOrder):
            if float(line['ts']) > maxTs:
                maxTs = float(line['ts'])

            uids[line['uid']] = {"src": line['id.orig_h'], "dst": line['id.resp_h'], "ts": float(line['ts']), "ds":int(line['orig_ip_bytes']), "used": False}

    # subtract 24 hours from the max timestamp
    minTs = math.floor(maxTs) - 86400
    # round min to start of hour
    minRoundedToStartOfHour = math.floor(minTs / 3600) * 3600
    return math.floor(minRoundedToStartOfHour), minTs, maxTs, uids

def plotHistogram(sortedData, start, end):
    size, scale = 1000, 10
    hist = pd.Series(sortedData)

    binz = np.linspace(start,end,25, endpoint=True)
    hist.plot.hist(#grid=True,
                    #    start=1647302276, stop=1647388791,
                    bins=binz,
                    #    bins=24,
                    #    bins=[1647302276,1647319762,1647360727,1647388791],

                    rwidth=0.9,
                    color='#607c8e')
    # plt.title('Connection Histogram')
    plt.xlabel('Timestamp')
    plt.ylabel('Conn Count')


    plt.yticks([0,1,2])

    xlabels=[]
    for ts in binz:
        # print(label)
        xlabels.append("%s" % datetime.fromtimestamp(ts))

    plt.xticks(binz, xlabels, rotation=90)

    # print("hist std", hist.std())

    plt.show()

# Abs returns two's complement 64 bit absolute value
def Abs(a):
	# mask = a >> 63
    mask = np.right_shift(a, 63)
    a = a ^ mask
    return a - mask

# Round returns rounded int64
def Round(f):
	return np.int64(np.floor(f + .5))

main()
# getMinMax()