#Malware Analysis Script for Pony by lee559 and slee118

import os
import json
import string

def jsonLoader(inputPath):
	"""
	Reads selected sample's json file and creates an dictionary
	object which represents that sample. The path of sample's
	json file is given as the parameter of the function.
	"""

	fp = open(inputPath, "r") #file descriptor to the json
    	data, = fp.readlines()
	fp.close()
	
	#divide each anti-virus entry using split
	data = data.replace('\n','')
	mylist = data.split('\",\"')

	currAV = ""
	i = 0

	output = {}

	#for loop to create dictionary object for the sample
	for x in mylist:

		if len(mylist) == 1:
			x = x
		elif i == 0:
			x = x+"\"}"
		elif i == len(mylist) - 1:
			x = "{\""+x
		else:
			x = "{\""+x+"\"}"

		node = json.loads(x)
		
		if len(node.keys()) == 0:
			return output

		#json file may have more than one value for the same key
		if node.keys()[0] != currAV:
			currAV = node.keys()[0]
			output[currAV] = [node[currAV]]
		else:
			output[currAV].append(node[currAV])				
		i += 1

	return output

def payloadChecker(jsonDict):
	"""
	This function analyzes all samples' payload descriptions from json.
	The function counts how many times each paylaod description is used
	to label each sample. Payloads which are mentioned more than 100 times
	are collected and created as a list since those are common definitions
	of pony malware from given anti-viruses.
	"""
	payloadDict = {}

	for x in jsonDict: #for each folder
		for y in jsonDict[x]: #for each av
			for z in jsonDict[x][y]: #for each payload
				if z in payloadDict:
					payloadDict[z] += 1
				else:
					payloadDict[z] = 1

	print "Payloads which are mentioned more than 1000 times\n"

	for x in payloadDict:
		if payloadDict[x] > 1000:
			print str(x)+" : "+str(payloadDict[x])

	return payloadDict

def avAnalyzer(freqTable, inputJson):
	"""
	Helper function which increments the frequency table for 
	given json object.
	"""
	for x in inputJson:
		if x in freqTable:
			freqTable[x] += 1
		else:
			freqTable[x] = 1	

def analyzer_1(jsonDict):
	"""
	Collects empty json files and writes their name to the output file.
	Each different json file has a list of {av: payload} pairs. The more
	diverse anti-viruses, the more probable that the sample is actually pony.
	Thus we created a list of malwares with less than five different anti-viruses
	associated. Then among those samples, we counted what kind of anti-viruses 
	defined those samples as malwares.
	"""
	freqTable = {}
	ctr = 0
	fp = open("candidates.txt", "a")
	fp.write("< Samples with empty avresults.json >\n\n")
	
	for x in jsonDict:
		if len(jsonDict[x]) <= 5:
			avAnalyzer(freqTable, jsonDict[x])
			if len(jsonDict[x]) > 0:
				ctr += 1
			else:
				fp.write(x + "\n")

	print "\nIn total, there are "+str(ctr)+" samples which are labeled as malware by 5 or less different kinds of anti-viruses.\n"


	for x in freqTable:
		print str(x)+" : "+str(freqTable[x])

	
	fp.write("\n")
	fp.close()
	return


def analyzer_2(popPayload, jsonDict):
	"""
	From payloadChecker(), we have found a list of common payloads.
	Now we examine samples with less than 10 different avs associated and
	check if those sample's are properly labeled as pony or not.
	"""

	fp = open("candidates.txt", "a")
	fp.write("< Samples with payload descriptions which are different from Pony >\n\n")

	for x in jsonDict: #for each folder
		ctr = 0
		if len(jsonDict[x]) > 10 or len(jsonDict[x]) == 0:
			continue

		for y in jsonDict[x]: #for each av
			for z in jsonDict[x][y]: #for each payload
				if z in popPayload.keys():
					ctr += 1
					break
		if ctr < 5:
			fp.write(x+"\n")
											
	fp.write("\n")
	fp.close()
	return
					
#main()

jsonDict = {}

if os.path.isfile("candidates.txt"):
	os.remove("candidates.txt")

for folder, subs, files in os.walk("."):
	for indivFile in files:
		if(indivFile.lower().endswith(".json")):	
			jsonPath = str(folder+"/"+indivFile)
			jsonObj = jsonLoader(jsonPath)
			jsonDict[str(folder)] = jsonObj

print "Total number of samples: "+str(len(jsonDict))+"\n"
		
popPayload = payloadChecker(jsonDict)
analyzer_1(jsonDict)
analyzer_2(popPayload, jsonDict)
